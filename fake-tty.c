/**
 * @file fake-tty.c
 * @brief Fake tty command for Linux.
 * 
 * @details
 * Runs a command in a pseudo terminal (pty),
 * so it behaves as if connected to a real terminal.
 *
 * ### Usage
 * @code
 *   fake-tty command [args ...]
 * @endcode
 *
 * ### License
 * MIT License
 *
 * @copyright Copyright (C) 2002-2025 SATO, Yoshiyuki
 */
static const char version_info[] = "@(#)$Header: fake-tty 0.5.1 2002-03-18/2025-06-20 yoshi389111 Exp $";

#define _XOPEN_SOURCE 600 // POSIX.1-2001

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // for strcasecmp()
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define PERROR(msg) perror( __FILE__ ":" TOSTRING(__LINE__) ": " msg )

#define EXIT_FAILURE_PARENT 1
#define EXIT_FAILURE_CHILD 2
#define EXIT_COMMAND_NOT_FOUND 127
#define BUFFSIZE 1024

/** Flag for window size change. */
volatile sig_atomic_t g_winch_flag = 0;
/** Flag for exit signal. */
volatile sig_atomic_t g_exit_flag = 0;
/** Exit signal number. */
volatile sig_atomic_t g_exit_signo = 0;

/** Original terminal settings for restoring later. */
struct termios g_orig_termios;

/** Flag indicating whether the terminal needs to be restored. */
int g_is_term_restore_needed = 0;

/** master file descriptor, used in cleanup() */
int g_master_fd = -1;

/** slave file descriptor, used in cleanup() */
int g_slave_fd = -1;

/** Flag indicating whether the current process is the child process. */
int g_in_child = 0;

/**
 * @brief Cleans up file descriptors and restores terminal settings if needed.
 */
void cleanup()
{
    if (g_in_child) {
        // close the duplicated pseudo-terminal (only in child process)
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

    } else if (g_is_term_restore_needed) {
        // restore original terminal settings (only in parent process)
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
        g_is_term_restore_needed = 0;
    }

    if (g_master_fd != -1) {
        close(g_master_fd);
        g_master_fd = -1;
    }

    if (g_slave_fd != -1) {
        close(g_slave_fd);
        g_slave_fd = -1;
    }
}

/**
 * @brief Checks for exit signal and cleans up if needed.
 *
 * This function should be called periodically in the main loop to check if an exit signal has been received.
 * If so, it cleans up resources and raises the signal again to terminate the process.
 */
void check_exit_signal()
{
    if (g_exit_flag) {
        cleanup();
        signal(g_exit_signo, SIG_DFL);
        raise(g_exit_signo);
    }
}

/**
 * @brief Propagates window size changes from the parent terminal to the child pty.
 * Called on SIGWINCH in the parent process.
 *
 * @param signo Signal number (unused).
 */
void handle_sigwinch(int signo __attribute__((unused)))
{
    g_winch_flag = 1;
}

/**
 * @brief Signal handler to restore terminal settings and exit.
 *
 * @param signo Signal number.
 */
void handle_exit_signal(int signo)
{
    g_exit_flag = 1;
    g_exit_signo = signo;
}

/**
 * @brief Reads data from the specified file descriptor into the buffer.
 *
 * @param fd_in File descriptor for input.
 * @param buff Buffer to read data into.
 * @param buffsize Size of the buffer.
 * @return Number of bytes read, 0 on EOF.
 */
ssize_t read_data(int fd_in, char *buff, size_t buffsize)
{
    while (1) {
        check_exit_signal();

        ssize_t ret = read(fd_in, buff, buffsize);

        if (ret == -1 && errno == EINTR) {
            // interrupted by signal, retry
            continue;

        } else if (ret == -1 && errno == EIO) {
            // EIO indicates EOF on a pipe or socket
            return 0; // EOF

        } else if (ret == -1) {
            PERROR("read()");
            exit(EXIT_FAILURE_PARENT);

        } else if (ret == 0) {
            return 0; // EOF

        } else {
            return ret;
        }
    }
}

/**
 * @brief Writes data from buffer to the specified file descriptor.
 *
 * @param fd_out File descriptor for output.
 * @param buff Buffer containing data to write.
 * @param len Length of data to write.
 * @return Number of bytes written, 0 on EOF.
 */
ssize_t write_data(int fd_out, const char *buff, ssize_t len)
{
    ssize_t written = 0;
    while (written < len) {
        check_exit_signal();

        ssize_t ret = write(fd_out, buff + written, len - written);

        if (ret == -1 && errno == EINTR) {
            // interrupted by signal, retry
            continue;

        } else if (ret == -1 && errno == EIO) {
            // EIO indicates EOF on a pipe or socket
            return 0; // EOF

        } else if (ret == -1) {
            PERROR("write()");
            exit(EXIT_FAILURE_PARENT);

        } else if (ret == 0) {
            // Normally, write() never returns 0.
            // But in case it does, treat as EOF to prevent infinite loop.
            return 0; // EOF
        }

        written += ret;
    }
    return written;
}

/**
 * @brief Relays data from one file descriptor to another.
 *
 * @param fd_in File descriptor for input.
 * @param fd_out File descriptor for output.
 * @return 1 on success, 0 on EOF.
 */
int relay_data(int fd_in, int fd_out)
{
    char buff[BUFFSIZE];
    ssize_t len = read_data(fd_in, buff, sizeof(buff));
    if (len == 0) {
        return 0; // EOF
    }

    if (write_data(fd_out, buff, len) == 0) {
        return 0; // EOF
    }
    return 1; // success
}

/**
 * @brief Sets up the child process side of the pseudo terminal and executes the command.
 *
 * @param argv Command line arguments for execvp().
 */
void child_side(char* argv[])
{
    // new session leader
    if (setsid() == -1) {
        PERROR("setsid()");
        exit(EXIT_FAILURE_CHILD);
    }

    // set controlling terminal
    if (ioctl(g_slave_fd, TIOCSCTTY, 0) == -1) {
        PERROR("ioctl(TIOCSCTTY)");
        exit(EXIT_FAILURE_CHILD);
    }

    // set foreground process group
    if (tcsetpgrp(g_slave_fd, getpid()) == -1) {
        PERROR("tcsetpgrp()");
        exit(EXIT_FAILURE_CHILD);
    }

    // slave -> stdin(child)
    if (dup2(g_slave_fd, STDIN_FILENO) == -1) {
        PERROR("dup2(STDIN)");
        exit(EXIT_FAILURE_CHILD);
    }

    // stdout(child) -> slave
    if (dup2(g_slave_fd, STDOUT_FILENO) == -1) {
        PERROR("dup2(STDOUT)");
        exit(EXIT_FAILURE_CHILD);
    }

    // stderr(child) -> slave
    if (dup2(g_slave_fd, STDERR_FILENO) == -1) {
        PERROR("dup2(STDERR)");
        exit(EXIT_FAILURE_CHILD);
    }

    if (close(g_slave_fd) == -1) {
        PERROR("close(slave)");
        g_slave_fd = -1;
        exit(EXIT_FAILURE_CHILD);
    }
    g_slave_fd = -1;

    // undocumented specification, always argv[argc] == NULL
    execvp(argv[0], argv);
    PERROR("execvp()");
    exit(EXIT_COMMAND_NOT_FOUND);
}

/**
 * @brief Changes the window size of the slave pseudo terminal.
 *
 * Note:
 * The slave fd is opened and closed each time in this function.
 * This is because if the parent process keeps the slave fd open,
 * it cannot detect EOF when the child process side closes its end.
 */
void check_win_size_change()
{
    if (g_winch_flag) {
        // handle window size change
        struct winsize size_info;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == 0) {
            int fd_slave_for_winsz = open(ptsname(g_master_fd), O_WRONLY | O_NOCTTY);
            if (fd_slave_for_winsz == -1) {
                PERROR("open(slave for winsz)");
                exit(EXIT_FAILURE_PARENT);
            }
            ioctl(fd_slave_for_winsz, TIOCSWINSZ, &size_info);
            close(fd_slave_for_winsz);
        }
        g_winch_flag = 0; // reset flag
    }
}

/**
 * @brief Handles the parent process side of the pseudo terminal,
 * relaying data between the terminal and the process.
 */
void parent_side()
{
    int is_stdin_closed = 0;
    while (1) {
        check_exit_signal();
        check_win_size_change();

        struct pollfd pfds[2];
        pfds[0].fd = g_master_fd;
        pfds[0].events = POLLIN;
        int nfds = 1;

        if (!is_stdin_closed) {
            pfds[1].fd = STDIN_FILENO;
            pfds[1].events = POLLIN;
            nfds = 2;
        }

        if (poll(pfds, nfds, -1) == -1) {
            if (errno == EINTR) {
                // interrupted by signal, retry
                continue;
            }
            PERROR("poll()");
            exit(EXIT_FAILURE_PARENT);
        }

        // master -> stdout(parent)
        if ((pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            if (relay_data(g_master_fd, STDOUT_FILENO) == 0) {
                // EOF or error
                break;
            }
        }

        // stdin(parent) -> master
        if (!is_stdin_closed && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            if (relay_data(STDIN_FILENO, g_master_fd) == 0) {
                // EOF or error
                is_stdin_closed = 1;
            }
        }
    }
    close(g_master_fd);
    g_master_fd = -1;
}

/**
 * @brief Entry point of the program.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status.
 */
int main(int argc, char*argv[])
{
    // ensure cleanup on exit
    atexit(cleanup);

    // check arguments
    if (argc < 2) {
        fprintf(stderr, "usage: %s command [args ...]\n", argv[0]);
        exit(EXIT_FAILURE_PARENT);
    }

    // check help. -h or --help
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("usage: %s command [args ...]\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    // check version. -V/-v or --version
    if (strcasecmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("%s\n", version_info);
        exit(EXIT_SUCCESS);
    }

    // open pty-master
    g_master_fd = posix_openpt(O_RDWR);
    if (g_master_fd == -1) {
        PERROR("open(master)");
        exit(EXIT_FAILURE_PARENT);
    }

    // grant access to pty-slave
    if (grantpt(g_master_fd) == -1) {
        PERROR("grantpt()");
        exit(EXIT_FAILURE_PARENT);
    }

    // unlock pty-slave
    if (unlockpt(g_master_fd) == -1) {
        PERROR("unlockpt()");
        exit(EXIT_FAILURE_PARENT);
    }

    // get pty-slave name
    char *slave_name = ptsname(g_master_fd);
    if (slave_name == NULL) {
        PERROR("ptsname()");
        exit(EXIT_FAILURE_PARENT);
    }

    // open pty-slave
    g_slave_fd = open(slave_name, O_RDWR);
    if (g_slave_fd == -1) {
        PERROR("open(slave)");
        exit(EXIT_FAILURE_PARENT);
    }

    if (isatty(STDIN_FILENO)) {
        // copy term info.
        struct termios termios;
        if (tcgetattr(STDIN_FILENO, &termios) == -1) {
            PERROR("tcgetattr(STDIN)");
            exit(EXIT_FAILURE_PARENT);
        }
        if (tcsetattr(g_slave_fd, TCSANOW, &termios) == -1) {
            PERROR("tcsetattr(slave)");
            exit(EXIT_FAILURE_PARENT);
        }

        // copy win-size
        struct winsize size_info;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == -1) {
            PERROR("ioctl(TIOCGWINSZ)");
            exit(EXIT_FAILURE_PARENT);
        }
        if (ioctl(g_slave_fd, TIOCSWINSZ, &size_info) == -1) {
            PERROR("ioctl(slave)");
            exit(EXIT_FAILURE_PARENT);
        }

        // save original terminal settings
        g_orig_termios = termios;
        g_is_term_restore_needed = 1;

        // set terminal to cbreak mode
        struct termios cbreak_termios = termios;
        cbreak_termios.c_lflag &= ~(ICANON | ECHO);
        cbreak_termios.c_lflag |= ISIG;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &cbreak_termios) == -1) {
            PERROR("tcsetattr(STDIN)");
            exit(EXIT_FAILURE_PARENT);
        }
    }

    // Set up signal handler (parent process only)
    struct sigaction sa_winch;
    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = handle_sigwinch;
    sigemptyset(&sa_winch.sa_mask);
    sa_winch.sa_flags = 0;
    if (sigaction(SIGWINCH, &sa_winch, NULL) == -1) {
        PERROR("sigaction(SIGWINCH)");
        exit(EXIT_FAILURE_PARENT);
    }

    struct sigaction sa_restore;
    memset(&sa_restore, 0, sizeof(sa_restore));
    sa_restore.sa_handler = handle_exit_signal;
    sigemptyset(&sa_restore.sa_mask);
    sa_restore.sa_flags = 0;
    if (sigaction(SIGINT,  &sa_restore, NULL) == -1) {
        PERROR("sigaction(SIGINT)");
        exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGTERM, &sa_restore, NULL) == -1) {
        PERROR("sigaction(SIGTERM)");
        exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGHUP,  &sa_restore, NULL) == -1) {
        PERROR("sigaction(SIGHUP)");
        exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGQUIT, &sa_restore, NULL) == -1) {
        PERROR("sigaction(SIGQUIT)");
        exit(EXIT_FAILURE_PARENT);
    }

    pid_t pid = fork();
    if (pid == -1) {
        PERROR("fork()");
        exit(EXIT_FAILURE_PARENT);

    } else if (pid == 0) {
        // child process side
        g_in_child = 1; // mark as child side
        g_is_term_restore_needed = 0; // child does not need to restore terminal

        if (close(g_master_fd) == -1) {
            PERROR("close(master)");
            g_master_fd = -1;
            exit(EXIT_FAILURE_CHILD);
        }
        g_master_fd = -1;
        // skip argv[0] (program name)
        child_side(argv + 1);
        // UNREACHABLE
        exit(EXIT_FAILURE_CHILD);
    }

    // parent process side
    if (close(g_slave_fd) == -1) {
        PERROR("close(slave)");
        g_slave_fd = -1;
        exit(EXIT_FAILURE_PARENT);
    }
    g_slave_fd = -1;

    parent_side();

    // cleanup before exiting
    cleanup();

    // wait for child process to finish
    // and exit with its status
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        PERROR("waitpid()");
        exit(EXIT_FAILURE_PARENT);
    }
    if (WIFEXITED(status)) {
        exit(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        // exit code 128 + signal number
        exit(128 + WTERMSIG(status));
    }
    // UNREACHABLE
    exit(EXIT_FAILURE_PARENT);
}

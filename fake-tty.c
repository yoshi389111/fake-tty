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
static const char version_info[] = "@(#)$Header: fake-tty 0.4.0 2002-03-18/2025-06-18 yoshi389111 Exp $";

#define _XOPEN_SOURCE 600 // POSIX.1-2001

#include <errno.h>
#include <fcntl.h>
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
struct termios orig_term_info;

/** Flag indicating whether the terminal needs to be restored. */
int g_restore_term_info = 0;

/** master file descriptor, used in cleanup() */
int g_master_fd = -1;

/** slave file descriptor, used in cleanup() */
int g_slave_fd = -1;

/**
 * @brief Cleans up file descriptors and restores terminal settings if needed.
 */
void cleanup()
{
    if (g_restore_term_info) {
        // restore original terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_term_info);
        g_restore_term_info = 0;
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
 * @brief Closes file descriptors and exits with the given code.
 *
 * @param exit_code Exit status code.
 */
void cleanup_and_exit(int exit_code)
{
    cleanup();
    exit(exit_code);
}

/**
 * @brief Reads data from the specified file descriptor into the buffer.
 *
 * @param fd_in File descriptor for input.
 * @param buff Buffer to read data into.
 * @param buffsize Size of the buffer.
 * @return Number of bytes read, 0 on EOF.
 */
ssize_t read_from_fd(int fd_in, char *buff, size_t buffsize)
{
    ssize_t ret;
    do {
        ret = read(fd_in, buff, buffsize);
    } while (ret == -1 && errno == EINTR);

    if (ret == 0) {
        return 0; // EOF
    } else if (ret == -1) {
        if (errno == EIO) {
            return 0; // EOF
        }
        perror("read()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    return ret;
}

/**
 * @brief Writes data from buffer to the specified file descriptor.
 *
 * @param fd_out File descriptor for output.
 * @param buff Buffer containing data to write.
 * @param len Length of data to write.
 * @return Number of bytes written, 0 on EOF.
 */
ssize_t write_to_fd(int fd_out, const char *buff, ssize_t len)
{
    ssize_t written = 0;
    while (written < len) {
        ssize_t ret;
        do {
            ret = write(fd_out, buff + written, len - written);
        } while (ret == -1 && errno == EINTR);

        if (ret == 0) {
            // Normally, write() never returns 0.
            // But in case it does, treat as EOF to prevent infinite loop.
            return 0; // EOF

        } else if (ret == -1) {
            if (errno == EIO) {
                return 0; // EOF
            }
            perror("write()");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
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
int relay_fd_data(int fd_in, int fd_out)
{
    char buff[BUFFSIZE];
    ssize_t len = read_from_fd(fd_in, buff, sizeof(buff));
    if (len == 0) {
        return 0; // EOF
    }

    if (write_to_fd(fd_out, buff, len) == 0) {
        return 0; // EOF
    }
    return 1; // success
}

/**
 * @brief Cleans up file descriptors and exits the child process with the given code.
 *
 * @param exit_code Exit status code.
 */
void cleanup_and_exit_child(int exit_code)
{
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if (g_master_fd != -1) {
        close(g_master_fd);
        g_master_fd = -1;
    }

    if (g_slave_fd != -1) {
        close(g_slave_fd);
        g_slave_fd = -1;
    }

    exit(exit_code);
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
        perror("setsid()");
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    // set controlling terminal
    if (ioctl(g_slave_fd, TIOCSCTTY, 0) == -1) {
        perror("ioctl(TIOCSCTTY)");
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    // slave -> stdin(child)
    if (dup2(g_slave_fd, STDIN_FILENO) == -1) {
        perror("dup2(STDIN)");
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    // stdout(child) -> slave
    if (dup2(g_slave_fd, STDOUT_FILENO) == -1) {
        perror("dup2(STDOUT)");
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    // stderr(child) -> slave
    if (dup2(g_slave_fd, STDERR_FILENO) == -1) {
        perror("dup2(STDERR)");
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    if (close(g_slave_fd) == -1) {
        perror("close(slave)");
        g_slave_fd = -1;
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }
    g_slave_fd = -1;

    // undocumented, but always argv[argc] == NULL
    execvp(argv[0], argv);
    perror("execvp()");
    cleanup_and_exit_child(EXIT_COMMAND_NOT_FOUND);
}

/**
 * @brief Handles the parent process side of the pseudo terminal,
 * relaying data between the terminal and the process.
 */
void parent_side()
{
    int maxfd = g_master_fd > STDIN_FILENO ? g_master_fd : STDIN_FILENO;
    int stdin_eof = 0;
    while (1) {
        if (g_exit_flag) {
            cleanup();
            signal(g_exit_signo, SIG_DFL);
            raise(g_exit_signo);
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_master_fd, &fds);
        if (!stdin_eof) {
            FD_SET(STDIN_FILENO, &fds);
        }

        if (select(maxfd + 1, &fds, NULL, NULL, NULL) == -1) {
            if (errno == EINTR) {
                // interrupted by signal, retry select
                continue;
            }
            perror("select()");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }

        if (g_winch_flag) {
            // handle window size change
            struct winsize size_info;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == 0) {
                int fd_slave_for_winsz = open(ptsname(g_master_fd), O_WRONLY | O_NOCTTY);
                if (fd_slave_for_winsz == -1) {
                    perror("open(slave for winsz)");
                    cleanup_and_exit(EXIT_FAILURE_PARENT);
                }
                ioctl(fd_slave_for_winsz, TIOCSWINSZ, &size_info);
                close(fd_slave_for_winsz);
            }
            g_winch_flag = 0; // reset flag
        }

        if (FD_ISSET(g_master_fd, &fds)) {
            // master -> stdout(parent)
            if (relay_fd_data(g_master_fd, STDOUT_FILENO) == 0) {
                // EOF
                break;
            }
        }

        if (!stdin_eof && FD_ISSET(STDIN_FILENO, &fds)) {
            // stdin(parent) -> master
            if (relay_fd_data(STDIN_FILENO, g_master_fd) == 0) {
                // EOF
                stdin_eof = 1; // mark stdin EOF
            }
        }
    }
    close(g_master_fd);
    g_master_fd = -1;
}

/**
 * @brief Propagates window size changes from the parent terminal to the child pty.
 * Called on SIGWINCH in the parent process.
 *
 * @param signo Signal number (unused).
 */
void sigwinch_handler(int signo __attribute__((unused)))
{
    g_winch_flag = 1;
}

/**
 * @brief Signal handler to restore terminal settings and exit.
 *
 * @param signo Signal number.
 */
void sig_restore_handler(int signo)
{
    g_exit_flag = 1;
    g_exit_signo = signo;
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
    // check arguments
    if (argc < 2) {
        fprintf(stderr, "usage: %s command [args ...]\n", argv[0]);
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    // check help. -h or --help
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("usage: %s command [args ...]\n", argv[0]);
        cleanup_and_exit(EXIT_SUCCESS);
    }

    // check version. -V/-v or --version
    if (strcasecmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("%s\n", version_info);
        cleanup_and_exit(EXIT_SUCCESS);
    }

    // open pty-master
    g_master_fd = posix_openpt(O_RDWR);
    if (g_master_fd == -1) {
        perror("open(master)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    // grant access to pty-slave
    if (grantpt(g_master_fd) == -1) {
        perror("grantpt()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    // unlock pty-slave
    if (unlockpt(g_master_fd) == -1) {
        perror("unlockpt()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    // get pty-slave name
    char *slave_name = ptsname(g_master_fd);
    if (slave_name == NULL) {
        perror("ptsname()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    // open pty-slave
    g_slave_fd = open(slave_name, O_RDWR);
    if (g_slave_fd == -1) {
        perror("open(slave)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    if (isatty(STDIN_FILENO)) {
        // copy term info.
        struct termios term_info;
        if (tcgetattr(STDIN_FILENO, &term_info) == -1) {
            perror("tcgetattr(STDIN)");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }
        if (tcsetattr(g_slave_fd, TCSANOW, &term_info) == -1) {
            perror("tcsetattr(slave)");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }

        // copy win-size
        struct winsize size_info;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == -1) {
            perror("ioctl(TIOCGWINSZ)");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }
        if (ioctl(g_slave_fd, TIOCSWINSZ, &size_info) == -1) {
            perror("ioctl(slave)");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }

        // save original terminal settings
        orig_term_info = term_info;
        g_restore_term_info = 1;

        // set terminal to cbreak mode
        struct termios cbreak_term_info = term_info;
        cbreak_term_info.c_lflag &= ~(ICANON | ECHO);
        cbreak_term_info.c_lflag |= ISIG;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &cbreak_term_info) == -1) {
            perror("tcsetattr(STDIN)");
            cleanup_and_exit(EXIT_FAILURE_PARENT);
        }
    }

    // Set up signal handler (parent process only)
    struct sigaction sa_winch;
    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = sigwinch_handler;
    sigemptyset(&sa_winch.sa_mask);
    sa_winch.sa_flags = 0;
    if (sigaction(SIGWINCH, &sa_winch, NULL) == -1) {
        perror("sigaction(SIGWINCH)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    struct sigaction sa_restore;
    memset(&sa_restore, 0, sizeof(sa_restore));
    sa_restore.sa_handler = sig_restore_handler;
    sigemptyset(&sa_restore.sa_mask);
    sa_restore.sa_flags = 0;
    if (sigaction(SIGINT,  &sa_restore, NULL) == -1) {
        perror("sigaction(SIGINT)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGTERM, &sa_restore, NULL) == -1) {
        perror("sigaction(SIGTERM)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGHUP,  &sa_restore, NULL) == -1) {
        perror("sigaction(SIGHUP)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }
    if (sigaction(SIGQUIT, &sa_restore, NULL) == -1) {
        perror("sigaction(SIGQUIT)");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    } else if (pid == 0) {
        // child process side
        g_restore_term_info = 0; // child does not need to restore terminal
        if (close(g_master_fd) == -1) {
            perror("close(master)");
            g_master_fd = -1;
            cleanup_and_exit_child(EXIT_FAILURE_CHILD);
        }
        g_master_fd = -1;
        // skip argv[0] (program name)
        child_side(argv + 1);
        // UNREACHABLE
        cleanup_and_exit_child(EXIT_FAILURE_CHILD);
    }

    // parent process side
    if (close(g_slave_fd) == -1) {
        perror("close(slave)");
        g_slave_fd = -1;
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }
    g_slave_fd = -1;

    parent_side();

    // cleanup before exiting
    cleanup();

    // wait for child process to finish
    // and exit with its status
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid()");
        cleanup_and_exit(EXIT_FAILURE_PARENT);
    }
    if (WIFEXITED(status)) {
        cleanup_and_exit(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        // exit code 128 + signal number
        cleanup_and_exit(128 + WTERMSIG(status));
    }
    // UNREACHABLE
    cleanup_and_exit(EXIT_FAILURE_PARENT);
}

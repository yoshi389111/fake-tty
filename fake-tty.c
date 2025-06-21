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
static const char version_info[] = "@(#)$Header: fake-tty 0.5.2 2002-03-18/2025-06-20 yoshi389111 Exp $";

#define _XOPEN_SOURCE 600 // POSIX.1-2001

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define PERROR(msg) do { perror( __FILE__ ":" TOSTRING(__LINE__) ": " msg ); } while (0)

/** @brief Exit code for the parent process. */
#define EXIT_FAILURE_PARENT (1)
/** @brief Exit code for the child process. */
#define EXIT_FAILURE_CHILD (2)
/** @brief Exit code for command not found. */
#define EXIT_COMMAND_NOT_FOUND (127)
/** @brief Buffer size for I/O operations. */
#define BUFFSIZE (1024)
/** @brief Truthy value for boolean expressions. */
#define TRUE (1)
/** @brief Falsy value for boolean expressions. */
#define FALSE (0)

/** @brief Flag for window size change. */
static volatile sig_atomic_t g_winch_flag = FALSE;
/** @brief Flag for exit signal. */
static volatile sig_atomic_t g_exit_flag = FALSE;
/** @brief Exit signal number. */
static volatile sig_atomic_t g_exit_signo = 0;

/** @brief Original terminal settings for restoring later. */
static struct termios g_orig_termios;

/** @brief Flag indicating whether the terminal needs to be restored. */
static int g_is_term_restore_needed = FALSE;

/** @brief master file descriptor. */
static int g_master_fd = -1;

/** @brief slave file descriptor. */
static int g_slave_fd = -1;

/** @brief Flag indicating whether the current process is the child process. */
static int g_in_child = FALSE;

/** @brief File descriptor for the original terminal (if needed). */
static int g_term_fd = -1;

/** @brief Closes the master file descriptor. */
static int close_master_fd()
{
    if (g_master_fd != -1) {
        int ret = close(g_master_fd);
        g_master_fd = -1;
        return ret;
    }
    return 0;
}

/** @brief Closes the slave file descriptor. */
static int close_slave_fd()
{
    if (g_slave_fd != -1) {
        int ret = close(g_slave_fd);
        g_slave_fd = -1;
        return ret;
    }
    return 0;
}

/**
 * @brief Cleans up file descriptors and restores terminal settings if needed.
 */
static void cleanup()
{
    if (g_in_child) {
        // close the duplicated pseudo-terminal (only in child process)
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

    } else if (g_is_term_restore_needed && g_term_fd != -1) {
        // restore original terminal settings (only in parent process)
        tcsetattr(g_term_fd, TCSANOW, &g_orig_termios);
        g_is_term_restore_needed = FALSE;
    }

    close_master_fd();
    close_slave_fd();
}

/**
 * @brief Checks for exit signal and cleans up if needed.
 *
 * This function should be called periodically in the main loop to check if an exit signal has been received.
 * If so, it cleans up resources and raises the signal again to terminate the process.
 */
static void check_exit_signal()
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
static void handle_sigwinch(int signo __attribute__((unused)))
{
    g_winch_flag = TRUE;
}

/**
 * @brief Signal handler to restore terminal settings and exit.
 *
 * @param signo Signal number.
 */
static void handle_exit_signal(int signo)
{
    g_exit_flag = TRUE;
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
static ssize_t read_data(int fd_in, char *buff, size_t buffsize)
{
    while (TRUE) {
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
static ssize_t write_data(int fd_out, const char *buff, ssize_t len)
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
static int relay_data(int fd_in, int fd_out)
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
static void child_side(char *argv[])
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

    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE_CHILD);
    }

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
static void check_win_size_change()
{
    if (g_winch_flag) {
        // handle window size change
        struct winsize size_info;
        if (ioctl(g_term_fd, TIOCGWINSZ, &size_info) == 0) {
            int fd_slave_for_winsz = open(ptsname(g_master_fd), O_RDWR | O_NOCTTY);
            if (fd_slave_for_winsz == -1) {
                PERROR("open(slave for winsz)");
                exit(EXIT_FAILURE_PARENT);
            }
            ioctl(fd_slave_for_winsz, TIOCSWINSZ, &size_info);
            close(fd_slave_for_winsz);
        }
        g_winch_flag = FALSE; // reset flag
    }
}

/**
 * @brief Handles the parent process side of the pseudo terminal,
 * relaying data between the terminal and the process.
 */
static void parent_side()
{
    int is_stdin_closed = FALSE;
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
                is_stdin_closed = TRUE;
            }
        }
    }
    close_master_fd();
}

/**
 * @brief Retrieve the terminal file descriptor.
 *
 * @return File descriptor for the terminal, or -1 if no terminal is available.
 */
static int get_term_fd() {
    if (isatty(STDIN_FILENO)) {
        return STDIN_FILENO;
    } else if (isatty(STDOUT_FILENO)) {
        return STDOUT_FILENO;
    } else if (isatty(STDERR_FILENO)) {
        return STDERR_FILENO;
    } else {
        return -1;
    }
}

/**
 * @brief Sets the terminal to cbreak mode.
 *
 * In cbreak mode, input is available immediately without waiting for a newline,
 * and input characters are not echoed to the terminal.
 */
static void set_cbreak_mode()
{
    struct termios cbreak_termios = g_orig_termios;
    cbreak_termios.c_lflag &= ~(ICANON | ECHO);
    cbreak_termios.c_lflag |= ISIG; // enable signals like SIGINT
    if (tcsetattr(g_term_fd, TCSANOW, &cbreak_termios) == -1) {
        PERROR("tcsetattr()");
        exit(EXIT_FAILURE_PARENT);
    }
    g_is_term_restore_needed = TRUE;
}

/**
 * @brief Prints usage error message and exits.
 *
 * @param progname Name of the program.
 */
void print_usage_error(const char *progname)
{
    fprintf(stderr, "Usage: %s command [args ...]\n", progname);
    fprintf(stderr, "Try '%s --help' for more information.\n", progname);
    exit(EXIT_FAILURE_PARENT);
}

/**
 * @brief Prints help message for the program.
 *
 * @param progname Name of the program.
 */
void print_help_message(const char *progname)
{
    printf("Usage: %s command [args ...]\n\n", progname);
    printf("Run a command in a pseudo terminal (pty), so it behaves as if connected to a real terminal.\n");
    printf("This is useful for commands that require a terminal interface.\n\n");
    printf("Options:\n");
    printf("  -h, --help        Show this help message and exit.\n");
    printf("  -V, -v, --version Show version information and exit.\n");
    exit(EXIT_SUCCESS);
}

/**
 * @brief Entry point of the program.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status.
 */
int main(int argc, char *argv[])
{
    // ensure cleanup on exit
    atexit(cleanup);

    // check arguments
    if (argc < 2) {
        print_usage_error(argv[0]);
        // UNREACHABLE
    }

    const char *progname = argv[0];
    char **child_args = argv + 1;

    // check help. -h or --help
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help_message(progname);
        // UNREACHABLE
    }

    // check version. -V/-v or --version
    if (
        strcmp(argv[1], "-V") == 0 ||
        strcmp(argv[1], "-v") == 0 ||
        strcmp(argv[1], "--version") == 0
    ) {
        printf("%s\n", version_info);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "--") == 0) {
        // skip the first argument if it is "--"
        child_args++;
    } else if (strncmp(argv[1], "-", 1) == 0) {
        // if the first argument starts with "-", it is considered an option
        fprintf(stderr, "error: invalid option '%s'\n", argv[1]);
        print_usage_error(progname);
        // UNREACHABLE
    }

    g_term_fd = get_term_fd();

    if (g_term_fd == -1) {
        // If no terminal is connected,
        // the pseudo terminal cannot be set up,
        // so a normal exec is executed.
        execvp(child_args[0], child_args);
        PERROR("execvp()");
        exit(EXIT_COMMAND_NOT_FOUND);
    }

    // retrieve terminal attributes
    if (tcgetattr(g_term_fd, &g_orig_termios) == -1) {
        PERROR("tcgetattr()");
        exit(EXIT_FAILURE_PARENT);
    }

    // retrieve window size
    struct winsize size_info;
    if (ioctl(g_term_fd, TIOCGWINSZ, &size_info) == -1) {
        PERROR("ioctl(TIOCGWINSZ)");
        exit(EXIT_FAILURE_PARENT);
    }

    // set terminal to cbreak mode
    set_cbreak_mode();

    // open pty master/slave
    if (openpty(&g_master_fd, &g_slave_fd, NULL, &g_orig_termios, &size_info) == -1) {
        PERROR("openpty()");
        exit(EXIT_FAILURE_PARENT);
    }

    // Set up signal handler for window size changes
    struct sigaction sa_winch = {0};
    sa_winch.sa_handler = handle_sigwinch;
    sigemptyset(&sa_winch.sa_mask);
    sa_winch.sa_flags = 0;
    if (sigaction(SIGWINCH, &sa_winch, NULL) == -1) {
        PERROR("sigaction(SIGWINCH)");
        exit(EXIT_FAILURE_PARENT);
    }

    // Set up signal handler for cleanup
    struct sigaction sa_restore = {0};
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
        g_in_child = TRUE; // mark as child side
        g_is_term_restore_needed = FALSE; // child does not need to restore terminal

        if (close_master_fd() == -1) {
            PERROR("close(master)");
            exit(EXIT_FAILURE_CHILD);
        }
        child_side(child_args);
        // UNREACHABLE
        exit(EXIT_FAILURE_CHILD);
    }

    // parent process side
    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE_PARENT);
    }

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

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
static const char version_info[] = "@(#)$Header: fake-tty 0.7.1 2002-03-18/2025-06-29 yoshi389111 Exp $";

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

/** @brief Exit code for command not found. */
#define EXIT_COMMAND_NOT_FOUND (127)
/** @brief Buffer size for I/O operations. */
#define BUFFSIZE (1024)
/** @brief Truthy value for boolean expressions. */
#define TRUE (1)
/** @brief Falsy value for boolean expressions. */
#define FALSE (0)

/** @brief Flag indicating whether SIGWINCH was received. */
static volatile sig_atomic_t g_sigwinch_flag = FALSE;

/** @brief Flag indicating whether SIGTSTP was received. */
static volatile sig_atomic_t g_sigtstp_flag = FALSE;

/** @brief Flag indicating whether SIGCONT was received. */
static volatile sig_atomic_t g_sigcont_flag = FALSE;

/** @brief Original terminal settings for restoring later. */
static struct termios g_orig_termios;

/** @brief Flag indicating whether the terminal needs to be restored. */
static int g_need_term_restore = FALSE;

/** @brief master file descriptor. */
static int g_master_fd = -1;

/** @brief slave file descriptor. */
static int g_slave_fd = -1;

/** @brief File descriptor for the original terminal (if needed). */
static int g_term_fd = -1;

/** @brief Process ID of the child process. -1 if not created. */
static pid_t g_child_pid = -1;

/**
 * @brief Prints usage error message.
 *
 * @param progname Name of the program.
 */
static void error_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s COMMAND [ARGS ...]\n", progname);
    fprintf(stderr, "Try '%s --help' for more information.\n", progname);
}

/**
 * @brief Prints help message for the program.
 *
 * @param progname Name of the program.
 */
static void show_help(const char *progname)
{
    printf("Usage: %s COMMAND [ARGS ...]\n\n", progname);
    printf("Run a command in a pseudo terminal (pty), so it behaves as if connected to a real terminal.\n");
    printf("This is useful for commands that require a terminal interface.\n\n");
    printf("Options:\n");
    printf("  -h, --help         Show this help message and exit.\n");
    printf("  -V, -v, --version  Show version information and exit.\n");
}

/**
 * @brief Parses command line arguments and checks for options.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Pointer to the command arguments for execvp().
 */
static char * const *parse_args(int argc, char * const *argv) {
    const char *progname = argv[0];
    char * const *command_args = argv + 1;

    if (argc < 2) {
        error_usage(progname);
        exit(EXIT_FAILURE);

    } else if (
        strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "--help") == 0
    ) {
        show_help(progname);
        exit(EXIT_SUCCESS);

    } else if (
        strcmp(argv[1], "-V") == 0 ||
        strcmp(argv[1], "-v") == 0 ||
        strcmp(argv[1], "--version") == 0
    ) {
        printf("%s\n", version_info);
        exit(EXIT_SUCCESS);

    } else if (strcmp(argv[1], "--") == 0) {
        // skip the first argument if it is "--"
        command_args++;
        return command_args;

    } else if (strncmp(argv[1], "-", 1) == 0) {
        // if the first argument starts with "-", it is considered an option
        fprintf(stderr, "error: invalid option '%s'\n", argv[1]);
        error_usage(progname);
        exit(EXIT_FAILURE);
    }

    return command_args;
}

/**
 * @brief Waits for the child process to finish and exits with its status.
 *
 * @param pid Process ID of the child process.
 */
static void wait_and_exit(pid_t pid)
{
    int status;
    while (TRUE) {
        if (waitpid(pid, &status, 0) == -1) {
            if (errno == EINTR) {
                // interrupted by signal, retry
                continue;
            }
            PERROR("waitpid()");
            exit(EXIT_FAILURE);
        }
        break;
    }
    if (WIFEXITED(status)) {
        exit(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        // exit code 128 + signal number
        exit(128 + WTERMSIG(status));
    }
}

/**
 * @brief Closes the master file descriptor.
 *
 * @return 0 on success, -1 on error.
 */
static int close_master_fd()
{
    if (g_master_fd != -1) {
        int ret = close(g_master_fd);
        g_master_fd = -1;
        return ret;
    }
    return 0;
}

/**
 * @brief Closes the slave file descriptor.
 *
 * @return 0 on success, -1 on error.
 */
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
    if (g_child_pid == getpid()) {
        // close the duplicated pseudo-terminal (only in child process)
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

    } else if (g_need_term_restore && g_term_fd != -1) {
        // restore original terminal settings (only in parent process)
        tcsetattr(g_term_fd, TCSANOW, &g_orig_termios);
        g_need_term_restore = FALSE;
    }

    close_master_fd();
    close_slave_fd();
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
 * @brief Synchronizes the terminal window size to the slave pseudo-terminal.
 *
 * This function opens the slave pseudo-terminal, retrieves the current
 * terminal window size, and sets it to the slave pseudo-terminal.
 */
static void sync_winsize_to_slave() {
    // Note:
    // The slave fd is opened and closed each time in this function.
    // This is because if the parent process keeps the slave fd open,
    // it cannot detect EOF when the child process side closes its end.
    g_slave_fd = open(ptsname(g_master_fd), O_RDWR | O_NOCTTY);
    if (g_slave_fd == -1) {
        PERROR("open(ptsname)");
        exit(EXIT_FAILURE);
    }

    struct winsize winsize_info;

    // retrieve window size from the terminal
    if (ioctl(g_term_fd, TIOCGWINSZ, &winsize_info) == -1) {
        PERROR("ioctl(TIOCGWINSZ)");
        exit(EXIT_FAILURE);
    }

    // set window size to the slave pseudo-terminal
    if (ioctl(g_slave_fd, TIOCSWINSZ, &winsize_info) == -1) {
        PERROR("ioctl(TIOCSWINSZ)");
        exit(EXIT_FAILURE);
    }

    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Sets the terminal to raw mode.
 *
 * @param term_fd File descriptor for the terminal.
 */
static void set_term_raw_mode(int term_fd)
{
    // set terminal to raw mode
    struct termios termios = g_orig_termios;
    termios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    termios.c_oflag &= ~(OPOST);
    termios.c_cflag |= (CS8);
    termios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    termios.c_cc[VMIN] = 1;
    termios.c_cc[VTIME] = 0;
    if (tcsetattr(term_fd, TCSANOW, &termios) == -1) {
        PERROR("tcsetattr()");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Sends an EOF to the master PTY if slave PTY is in canonical mode.
 */
static void send_eof_if_canonical()
{
    g_slave_fd = open(ptsname(g_master_fd), O_RDWR | O_NOCTTY);
    if (g_slave_fd == -1) {
        PERROR("open(ptsname)");
        exit(EXIT_FAILURE);
    }

    struct termios termios;
    if (tcgetattr(g_slave_fd, &termios) == -1) {
        PERROR("tcgetattr()");
        exit(EXIT_FAILURE);
    }

    if (termios.c_lflag & ICANON) {
        cc_t veof = termios.c_cc[VEOF];
        while (write(g_master_fd, &veof, 1) == -1) {
            if (errno == EINTR) {
                // interrupted by signal, retry
                continue;
            } else if (errno == EIO) {
                // EIO indicates EOF on a pipe or socket
                break; // EOF
            } else {
                PERROR("write()");
                exit(EXIT_FAILURE);
            }
        }
    }

    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Sets up a signal handler for the specified signal.
 *
 * @param signo Signal number.
 * @param handler Signal handler function.
 * @return 0 on success, -1 on error.
 */
static int setup_sigaction(int signo, void (*handler)(int))
{
    struct sigaction sa = {0};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    return sigaction(signo, &sa, NULL);
}

/**
 * @brief Signal handler to handle exit signals.
 *
 * @param signo Signal number.
 */
static void handle_exit_signal(int signo)
{
    if (g_child_pid != -1) {
        // send signal to process group of the child
        kill(-g_child_pid, signo);
    }
}

static void handle_sigtstp(int signo __attribute__((unused)))
{
    g_sigtstp_flag = TRUE;
}

static void handle_sigcont(int signo __attribute__((unused)))
{
    g_sigcont_flag = TRUE;
    // window size needs to be updated
    g_sigwinch_flag = TRUE;
}

/**
 * @brief Propagates window size changes from the parent terminal to the child pty.
 * Called on SIGWINCH in the parent process.
 *
 * @param signo Signal number (unused).
 */
static void handle_sigwinch(int signo __attribute__((unused)))
{
    g_sigwinch_flag = TRUE;
}

/**
 * @brief Checks for pending signals and handles them accordingly.
 */
static void check_signals()
{
    if (g_sigcont_flag) {
        // Reset the signal handler that was cleared by SIGTSTP to SIGCONT
        setup_sigaction(SIGCONT, handle_sigcont);
        if (g_child_pid != -1) {
            // send signal to child process group
            kill(-g_child_pid, SIGCONT);
        }
        g_sigcont_flag = FALSE;
    }

    if (g_sigtstp_flag) {
        if (g_child_pid != -1) {
            // send signal to child process group
            kill(-g_child_pid, SIGTSTP);
        }
        // send SIGTSTP to self to stop the parent process
        setup_sigaction(SIGTSTP, SIG_DFL);
        g_sigtstp_flag = FALSE;
        raise(SIGTSTP);
    }

    if (g_sigwinch_flag) {
        // handle window size change
        sync_winsize_to_slave();
        g_sigwinch_flag = FALSE;
    }
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
        check_signals();

        ssize_t ret = read(fd_in, buff, buffsize);

        if (ret == -1 && errno == EINTR) {
            // interrupted by signal, retry
            continue;

        } else if (ret == -1 && errno == EIO) {
            // EIO indicates EOF on a pipe or socket
            return 0; // EOF

        } else if (ret == -1) {
            PERROR("read()");
            exit(EXIT_FAILURE);

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
        check_signals();

        ssize_t ret = write(fd_out, buff + written, len - written);

        if (ret == -1 && errno == EINTR) {
            // interrupted by signal, retry
            continue;

        } else if (ret == -1 && errno == EIO) {
            // EIO indicates EOF on a pipe or socket
            return 0; // EOF

        } else if (ret == -1) {
            PERROR("write()");
            exit(EXIT_FAILURE);

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
static void child_exec(char * const *argv)
{
    if (close_master_fd() == -1) {
        PERROR("close(master)");
        exit(EXIT_FAILURE);
    }

    // new session leader
    if (setsid() == -1) {
        PERROR("setsid()");
        exit(EXIT_FAILURE);
    }

    // set controlling terminal
    if (ioctl(g_slave_fd, TIOCSCTTY, 0) == -1) {
        PERROR("ioctl(TIOCSCTTY)");
        exit(EXIT_FAILURE);
    }

    // set foreground process group
    if (tcsetpgrp(g_slave_fd, g_child_pid) == -1) {
        PERROR("tcsetpgrp()");
        exit(EXIT_FAILURE);
    }

    // slave -> stdin(child)
    if (dup2(g_slave_fd, STDIN_FILENO) == -1) {
        PERROR("dup2(STDIN)");
        exit(EXIT_FAILURE);
    }

    // stdout(child) -> slave
    if (dup2(g_slave_fd, STDOUT_FILENO) == -1) {
        PERROR("dup2(STDOUT)");
        exit(EXIT_FAILURE);
    }

    // stderr(child) -> slave
    if (dup2(g_slave_fd, STDERR_FILENO) == -1) {
        PERROR("dup2(STDERR)");
        exit(EXIT_FAILURE);
    }

    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE);
    }

    // Set up signal handlers to ignore signals in the child process
    if (setup_sigaction(SIGINT, SIG_IGN) == -1) {
        PERROR("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    if (setup_sigaction(SIGTERM, SIG_IGN) == -1) {
        PERROR("sigaction(SIGTERM)");
        exit(EXIT_FAILURE);
    }
    if (setup_sigaction(SIGHUP, SIG_IGN) == -1) {
        PERROR("sigaction(SIGHUP)");
        exit(EXIT_FAILURE);
    }
    if (setup_sigaction(SIGQUIT, SIG_IGN) == -1) {
        PERROR("sigaction(SIGQUIT)");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == -1) {
        PERROR("fork()");
        exit(EXIT_FAILURE);

    } else if (pid == 0) {
        // grandchild process side
        // undocumented specification, always argv[argc] == NULL
        execvp(argv[0], argv);
        PERROR("execvp()");
        exit(EXIT_COMMAND_NOT_FOUND);
    }

    wait_and_exit(pid);
    // UNREACHABLE
}

/**
 * @brief Handles the parent process side of the pseudo terminal,
 * relaying data between the terminal and the process.
 */
static void parent_mainloop()
{
    if (close_slave_fd() == -1) {
        PERROR("close(slave)");
        exit(EXIT_FAILURE);
    }

    // Set up signal handler for window size changes
    if (setup_sigaction(SIGWINCH, handle_sigwinch) == -1) {
        PERROR("sigaction(SIGWINCH)");
        exit(EXIT_FAILURE);
    }

    // Set up signal handler for propagating exit signals to the child process group
    if (setup_sigaction(SIGINT, handle_exit_signal) == -1) {
        PERROR("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    if (setup_sigaction(SIGTERM, handle_exit_signal) == -1) {
        PERROR("sigaction(SIGTERM)");
        exit(EXIT_FAILURE);
    }
    if (setup_sigaction(SIGQUIT, handle_exit_signal) == -1) {
        PERROR("sigaction(SIGQUIT)");
        exit(EXIT_FAILURE);
    }

    // Set up signal handler for SIGTSTP
    if (setup_sigaction(SIGTSTP, handle_sigtstp) == -1) {
        PERROR("sigaction(SIGTSTP)");
        exit(EXIT_FAILURE);
    }

    // Set up signal handler for SIGCONT
    if (setup_sigaction(SIGCONT, handle_sigcont) == -1) {
        PERROR("sigaction(SIGCONT)");
        exit(EXIT_FAILURE);
    }

    // set terminal to raw mode
    set_term_raw_mode(g_term_fd);

    const int POLL_EVENTS = POLLIN | POLLHUP | POLLERR;

    struct pollfd pfds[2];
    pfds[0].fd = g_master_fd;
    pfds[0].events = POLL_EVENTS;
    pfds[1].fd = STDIN_FILENO;
    pfds[1].events = POLL_EVENTS;

    int is_stdin_closed = FALSE;
    while (1) {
        check_signals();

        int nfds = is_stdin_closed ? 1 : 2;
        int timeout = is_stdin_closed ? 1000 : -1;

        int ret = poll(pfds, nfds, timeout);
        if (ret == -1 && errno == EINTR) {
            // interrupted by signal, retry
            continue;

        } else if (ret == -1) {
            PERROR("poll()");
            exit(EXIT_FAILURE);

        } else if (ret == 0) {
            // timeout
            break;
        }

        // master -> stdout(parent)
        if ((pfds[0].revents & POLL_EVENTS) != 0) {
            if (relay_data(g_master_fd, STDOUT_FILENO) == 0) {
                // EOF or error
                break;
            }
        }

        // stdin(parent) -> master
        if (!is_stdin_closed && (pfds[1].revents & POLL_EVENTS) != 0) {
            if (relay_data(STDIN_FILENO, g_master_fd) == 0) {
                // EOF or error
                is_stdin_closed = TRUE;
                send_eof_if_canonical();
            }
        }
    }

    close_master_fd();

    // wait for child process to finish
    // and exit with its status
    wait_and_exit(g_child_pid);
    // UNREACHABLE
}

/**
 * @brief Entry point of the program.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status.
 */
int main(int argc, char * const *argv)
{
    // ensure cleanup on exit
    atexit(cleanup);

    // check options and parse arguments
    char * const *command_args = parse_args(argc, argv);

    g_term_fd = get_term_fd();
    if (g_term_fd == -1) {
        // If no terminal is connected,
        // the pseudo terminal cannot be set up,
        // so a normal exec is executed.
        // Note: undocumented specification, always argv[argc] == NULL
        execvp(command_args[0], command_args);
        PERROR("execvp()");
        exit(EXIT_COMMAND_NOT_FOUND);
    }

    // retrieve terminal attributes
    if (tcgetattr(g_term_fd, &g_orig_termios) == -1) {
        PERROR("tcgetattr()");
        exit(EXIT_FAILURE);
    }
    g_need_term_restore = TRUE;

    // retrieve window size
    struct winsize winsize_info;
    if (ioctl(g_term_fd, TIOCGWINSZ, &winsize_info) == -1) {
        PERROR("ioctl(TIOCGWINSZ)");
        exit(EXIT_FAILURE);
    }

    // open pty master/slave
    if (openpty(&g_master_fd, &g_slave_fd, NULL, &g_orig_termios, &winsize_info) == -1) {
        PERROR("openpty()");
        exit(EXIT_FAILURE);
    }

    g_child_pid = fork();
    if (g_child_pid == -1) {
        PERROR("fork()");
        exit(EXIT_FAILURE);

    } else if (g_child_pid == 0) {
        // child process side
        g_child_pid = getpid();
        child_exec(command_args);
        // UNREACHABLE
    }

    // main loop for the parent process
    parent_mainloop();
    // UNREACHABLE
    exit(EXIT_FAILURE);
}

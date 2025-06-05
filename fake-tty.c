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
static const char version_info[] = "@(#)$Header: fake-tty 0.3 2002-03-18/2025-06-06 yoshi389111 Exp $";

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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE_PARENT 1
#define EXIT_FAILURE_CHILD 2
#define EXIT_COMMAND_NOT_FOUND 127
#define BUFFSIZE 1024

/** Flag for window size change. */
volatile sig_atomic_t g_winch_flag = 0;

/**
 * @brief Reads data from the specified file descriptor into the buffer.
 *
 * @param fd_in File descriptor for input.
 * @param buff Buffer to read data into.
 * @param buffsize Size of the buffer.
 * @return Number of bytes read, -1 on EOF.
 */
ssize_t read_from_fd(int fd_in, char *buff, size_t buffsize)
{
    ssize_t ret;
    do {
        ret = read(fd_in, buff, buffsize);
    } while (ret == -1 && errno == EINTR);

    if (ret == 0) {
        return -1; // EOF
    } else if (ret == -1) {
        if (errno == EIO) {
            return -1; // EOF
        }
        perror("read()");
        exit(EXIT_FAILURE_PARENT);
    }

    return ret;
}

/**
 * @brief Writes data from buffer to the specified file descriptor.
 *
 * @param fd_out File descriptor for output.
 * @param buff Buffer containing data to write.
 * @param len Length of data to write.
 */
void write_to_fd(int fd_out, const char *buff, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t ret;
        do {
            ret = write(fd_out, buff + written, len - written);
        } while (ret == -1 && errno == EINTR);

        if (ret == -1) {
            perror("write()");
            exit(EXIT_FAILURE_PARENT);
        }
        written += ret;
    }
}

/**
 * @brief Relays data from one file descriptor to another.
 *
 * @param fd_in File descriptor for input.
 * @param fd_out File descriptor for output.
 * @return 0 on success, -1 on EOF.
 */
int relay_fd_data(int fd_in, int fd_out)
{
    char buff[BUFFSIZE];
    ssize_t len = read_from_fd(fd_in, buff, sizeof(buff));
    if (len == -1) {
        return -1; // EOF
    }

    write_to_fd(fd_out, buff, len);
    return 0; // success
}

/**
 * @brief Closes file descriptors and exits with the given code.
 *
 * @param fd_master File descriptor for the master side, or -1 if unused.
 * @param fd_slave File descriptor for the slave side, or -1 if unused.
 * @param exit_code Exit status code.
 */
void cleanup_and_exit(int fd_master, int fd_slave, int exit_code)
{
    if (fd_master != -1) {
        close(fd_master);
    }
    if (fd_slave != -1) {
        close(fd_slave);
    }
    exit(exit_code);
}

/**
 * @brief Sets up the child process side of the pseudo terminal and executes the command.
 *
 * @param fd_slave File descriptor for slave side.
 * @param argv Command line arguments for execvp().
 */
void child_side(int fd_slave, char* argv[])
{
    // new session leader
    if (setsid() == -1) {
        perror("setsid()");
        cleanup_and_exit(-1, fd_slave, EXIT_FAILURE_CHILD);
    }

    // set controlling terminal
    if (ioctl(fd_slave, TIOCSCTTY, 0) == -1) {
        perror("ioctl(TIOCSCTTY)");
        cleanup_and_exit(-1, fd_slave, EXIT_FAILURE_CHILD);
    }

    // slave -> stdin(child)
    if (dup2(fd_slave, STDIN_FILENO) == -1) {
        perror("dup2(STDIN)");
        cleanup_and_exit(-1, fd_slave, EXIT_FAILURE_CHILD);
    }

    // stdout(child) -> slave
    if (dup2(fd_slave, STDOUT_FILENO) == -1) {
        perror("dup2(STDOUT)");
        cleanup_and_exit(-1, fd_slave, EXIT_FAILURE_CHILD);
    }

    // stderr(child) -> slave
    if (dup2(fd_slave, STDERR_FILENO) == -1) {
        perror("dup2(STDERR)");
        cleanup_and_exit(-1, fd_slave, EXIT_FAILURE_CHILD);
    }

    if (close(fd_slave) == -1) {
        perror("close(slave)");
        exit(EXIT_FAILURE_CHILD);
    }

    // undocumented, but always argv[argc] == NULL
    execvp(argv[0], argv);
    perror("execvp()");
    exit(EXIT_COMMAND_NOT_FOUND);
}

/**
 * @brief Handles the parent process side of the pseudo terminal,
 * relaying data between the terminal and the process.
 *
 * @param fd_master File descriptor for master side.
 */
void parent_side(int fd_master)
{
    int maxfd = fd_master > STDIN_FILENO ? fd_master : STDIN_FILENO;
    while (1) {
        fd_set fds;
        int ret;
        do {
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);
            FD_SET(fd_master, &fds);

            ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
        } while (ret == -1 && errno == EINTR);

        if (ret == -1) {
            perror("select()");
            exit(EXIT_FAILURE_PARENT);
        }

        if (g_winch_flag) {
            // handle window size change
            struct winsize size_info;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == 0) {
                int fd_slave_for_winsz = open(ptsname(fd_master), O_WRONLY | O_NOCTTY);
                if (fd_slave_for_winsz == -1) {
                    perror("open(slave for winsz)");
                    exit(EXIT_FAILURE_PARENT);
                }
                ioctl(fd_slave_for_winsz, TIOCSWINSZ, &size_info);
                close(fd_slave_for_winsz);
            }
            g_winch_flag = 0; // reset flag
        }

        if (FD_ISSET(fd_master, &fds)) {
            // master -> stdout(parent)
            if (relay_fd_data(fd_master, STDOUT_FILENO) == -1) {
                // EOF
                break;
            }

        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            // stdin(parent) -> master
            if (relay_fd_data(STDIN_FILENO, fd_master) == -1) {
                // EOF
                break;
            }
        }
    }
    close(fd_master);
}

/**
 * @brief Propagates window size changes from the parent terminal to the child pty.
 * Called on SIGWINCH in the parent process.
 *
 * @param signo Signal number (unused).
 */
void sigwinch_handler(int signo)
{
    g_winch_flag = 1;
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
    int fd_master = posix_openpt(O_RDWR);
    if (fd_master == -1) {
        perror("open(master)");
        exit(EXIT_FAILURE_PARENT);
    }

    // grant access to pty-slave
    if (grantpt(fd_master) == -1) {
        perror("grantpt()");
        cleanup_and_exit(fd_master, -1, EXIT_FAILURE_PARENT);
    }

    // unlock pty-slave
    if (unlockpt(fd_master) == -1) {
        perror("unlockpt()");
        cleanup_and_exit(fd_master, -1, EXIT_FAILURE_PARENT);
    }

    // get pty-slave name
    char *slave_name = ptsname(fd_master);
    if (slave_name == NULL) {
        perror("ptsname()");
        cleanup_and_exit(fd_master, -1, EXIT_FAILURE_PARENT);
    }

    // open pty-slave
    int fd_slave = open(slave_name, O_RDWR);
    if (fd_slave == -1) {
        perror("open(slave)");
        cleanup_and_exit(fd_master, -1, EXIT_FAILURE_PARENT);
    }

    if (isatty(STDIN_FILENO)) {
        // copy term info.
        struct termios term_info;
        if (tcgetattr(STDIN_FILENO, &term_info) == -1) {
            perror("tcgetattr(STDIN)");
            cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
        }

        if (tcsetattr(fd_slave, TCSANOW, &term_info) == -1) {
            perror("tcsetattr(slave)");
            cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
        }

        // copy win-size
        struct winsize size_info;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size_info) == -1) {
            perror("ioctl(TIOCGWINSZ)");
            cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
        }

        if (ioctl(fd_slave, TIOCSWINSZ, &size_info) == -1) {
            perror("ioctl(slave)");
            cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
        }
    }

    // Set up signal handler (parent process only)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigwinch_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGWINCH, &sa, NULL) == -1) {
        perror("sigaction(SIGWINCH)");
        cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork()");
        cleanup_and_exit(fd_master, fd_slave, EXIT_FAILURE_PARENT);
    } else if (pid == 0) {
        // child process side
        if (close(fd_master) == -1) {
            perror("close(master)");
            exit(EXIT_FAILURE_CHILD);
        }
        // skip argv[0] (program name)
        child_side(fd_slave, argv + 1);
        exit(EXIT_FAILURE_CHILD);
    }

    // parent process side
    if (close(fd_slave) == -1) {
        perror("close(slave)");
        cleanup_and_exit(fd_master, -1, EXIT_FAILURE_PARENT);
    }

    parent_side(fd_master);

    // wait for child process to finish
    // and exit with its status
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        exit(WEXITSTATUS(status));
    }
    exit(EXIT_FAILURE_PARENT);
}

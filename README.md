# FAKE-TTY

## NAME

`fake-tty` - run a command in a pseudo terminal (pty) for linux

## SYNOPSIS

```shell
fake-tty [-h | --help | -v | -V | --version] COMMAND [ARGS...]
```

## DESCRIPTION

`fake-tty` executes the specified command in a pseudo terminal (pty), making the command behave as if it is connected to a real terminal. This is useful for scripting, automation, or when you need terminal-specific behavior from programs.

## OPTIONS

- `-h`, `--help`
  - Show help message and exit.

- `-v`, `-V`, `--version`
  - Show version information and exit.

## EXAMPLES

```console
$ ls
LICENSE  Makefile  README.md  fake-tty  fake-tty.c
$ ls | cat
LICENSE
Makefile
README.md
fake-tty
fake-tty.c
$ ./fake-tty ls | cat
LICENSE  Makefile  README.md  fake-tty  fake-tty.c
```

## REQUIREMENTS

- Linux (only supported platform)
- C compiler (e.g., gcc 4.0+)
- C Standard Library (e.g., glibc 2.3+)
- make utility

## INSTALLATION

```sh
git clone https://github.com/yoshi389111/fake-tty.git
cd fake-tty
make
```

Move `fake-tty` to a directory in your `PATH` if needed.

## LICENSE

MIT License

&copy; 2002-2025 SATO, Yoshiyuki

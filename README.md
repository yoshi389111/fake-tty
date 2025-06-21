# FAKE-TTY

## NAME

`fake-tty` \- run a command in a pseudo terminal (pty) for linux

## SYNOPSIS

`fake-tty <command> [args...]`

`fake-tty [-h | --help | -v | -V | --version]`

## DESCRIPTION

`fake-tty` executes the specified command in a pseudo terminal (pty), making the command behave as if it is connected to a real terminal. This is useful for scripting, automation, or when you need terminal-specific behavior from programs.

## OPTIONS

| Option                | Description         |
|-----------------------|--------------------|
| \-h, --help           | Show help message  |
| \-v, \-V, --version   | Show version info  |

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

## AUTHOR

Copyright (c) 2002-2025 SATO, Yoshiyuki

# fake-tty

## Overview

fake-tty is a tool that runs commands in a pseudo terminal (pty), making them behave as if they are connected to a real terminal.

## Features

- Run any command via a pty
- Reproduce terminal-specific behavior
- Useful for scripting and automation

## Requirements

- Linux (This program is Linux-only and does not support other operating systems.)
- C compiler (e.g., `gcc 4.0+`)
- C Standard Library (e.g., `glibc 2.3+`)
- Make utility

## Installation

```sh
git clone https://github.com/yoshi389111/fake-tty.git
cd fake-tty
make
```

If necessary, move `fake-tty` to a bin directory that is defined in your `PATH` environment variable.

## Usage

```sh
fake-tty <command> [args...]
```

Example:

```console
$ ls
file1.txt  file2.txt  dir1/  dir2/
$ ls | cat
file1.txt
file2.txt
dir1/
dir2/
$ ./fake-tty ls | cat
file1.txt  file2.txt  dir1/  dir2/
```

## Options

|      Option       | Description  |
| :---------------: | :----------- |
|    -h, --help     | Show help    |
| -v, -V, --version | Show version |

## License

MIT License

Copyright &copy; 2002-2025 SATO, Yoshiyuki

# fake-tty

## Overview

fake-tty is a tool that runs commands in a pseudo terminal (pty), making them behave as if they are connected to a real terminal.

## Features

- Run any command via a pty
- Reproduce terminal-specific behavior
- Useful for scripting and automation

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

```
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

> [!CAUTION]
> Do not run commands that change terminal settings, such as vi or less.

## Options

|      Option       | Description  |
| :---------------: | :----------- |
|    -h, --help     | Show help    |
| -v, -V, --version | Show version |

## License

MIT License

Copyright (C) 2002-2025 SATO, Yoshiyuki

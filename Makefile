CC = gcc
CFLAGS = -Wall -O2

.PHONY: all clean

all: fake-tty

fake-tty: fake-tty.c
	$(CC) $(CFLAGS) -o fake-tty fake-tty.c

clean:
	rm -f fake-tty

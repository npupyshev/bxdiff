CC = gcc
CFLAGS = -arch x86_64 -I/usr/local/include -lcrypto -llzma

all:
	$(CC) $(CFLAGS) bxpatch.c -o bxpatch
	$(CC) $(CFLAGS) bxdiff.c lzmaio.c -o bxdiff

install:
	cp bxpatch /usr/local/bin
	cp bxdiff /usr/local/bin

CC = clang
CFLAGS = -arch armv7 -arch arm64 -I/opt/local/include -llzma -Wall -miphoneos-v$

all:
        xcrun -sdk iphoneos $(CC) $(CFLAGS) main.c -o bxdiff
        ldid -S bxdiff

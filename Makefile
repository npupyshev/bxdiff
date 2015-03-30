CC = clang
CFLAGS = -arch armv7 -arch arm64 -I/opt/local/include -llzma -Wall -miphoneos-version-min=5.0

all:
	xcrun -sdk iphoneos $(CC) $(CFLAGS) main.c -o bxpatch
	ldid -S bxpatch

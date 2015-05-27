# bxdiff/bxpatch
Patching utility that uses BXDIFF41 patch format.
Uses XZ Tools LZMA library for decompression.
This utility is licensed under terms of GNU GPLv2 license.
Utility was tested on iOS 8.1.2 to 8.3 update and verified by
launching the patched executable and feeding the executable to IDA.

# usage
bxpatch <in file> <out file> <bxdiff patch file>

# requirements
1. ldid (if you're building iOS version)
2. liblzma (I used one from MacPorts)

# build
- make # build for iOS
- make -f Makefile.osx # build for OS X

# bxdiff
Patching utility that uses BXDIFF41 patch format.
Uses XZ Tools LZMA library for decompression.
This utility is licensed under terms of GNU GPLv2 license.

# usage
bxpatch <in file> <out file> <bxdiff patch file>

# requirements
1. ldid
2. liblzma (I used one from MacPorts)

# build
- make # build for iOS
- make -f Makefile.osx # build for OS X

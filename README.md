# bxdiff/bxpatch
Patching utility that uses BXDIFF40 and BXDIFF41 patch format.
Uses XZ Tools LZMA library for decompression.

# usage
bxpatch <in file> <out file> <bxdiff patch file>

# requirements
1. ldid (if you're building iOS version)
2. liblzma (I used one from MacPorts)
3. libcrypto

# build
- make # build for iOS
- make -f Makefile.osx # build for OS X

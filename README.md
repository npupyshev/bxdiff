# bxdiff/bxpatch
Patching utility that uses BXDIFF40 and BXDIFF41 patch format.
Uses XZ Tools LZMA library.

# usage
bxdiff <in file> <out file> <bxdiff patch file>
bxpatch <in file> <out file> <bxdiff patch file>

# requirements
1. ldid (if you're building iOS version)
2. liblzma (I used one from MacPorts)
3. libcrypto

# build
- make # build for OS X
- make -f Makefile.ios # build for iOS

# bxdiff
Patching utility that uses BXDIFF41 patch format.
Uses XZ Tools LZMA library for decompression.
This utility is licensed under terms of GNU GPLv2 license.
# build
You'll need liblzma and ldid.
On Mac OS just run:
sudo port install xz
xcrun -sdk iphoneos clang main.c -llzma -I/opt/local/include -arch armv7 -arch arm64 -no-integrated-as -DINLINE_IT_ALL=1 -Wall -o bxdiff -miphoneos-version-min=5.0; ldid -S bxdiff

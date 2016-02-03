//
//  lzmaio.h
//  bxdiff
//
//  Created by Никита Пупышев on 03.02.16.
//  Copyright © 2016 Никита Пупышев. All rights reserved.
//

#ifndef lzmaio_h
#define lzmaio_h

#include <stdio.h>
#include <lzma.h>

typedef struct {
	FILE *f;
	lzma_stream strm;
	void *buffer;
	size_t bs;
	lzma_action action;
} LZMA_FILE;

LZMA_FILE *lzma_xzWriteOpen(lzma_ret *error, FILE *f, int blockSize, int level);
void lzma_xzWrite(lzma_ret *error, LZMA_FILE *file, const void *buf, size_t len);
void lzma_xzClose(lzma_ret *error, LZMA_FILE *file);

#endif /* lzmaio_h */

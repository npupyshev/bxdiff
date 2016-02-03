//
//  lzmaio.c
//  bxdiff
//
//  Created by Никита Пупышев on 03.02.16.
//  Copyright © 2016 Никита Пупышев. All rights reserved.
//

#include "lzmaio.h"
#include <stdlib.h>
#include <string.h>

LZMA_FILE *lzma_xzWriteOpen(lzma_ret *error, FILE *f, int blockSize, int level) {
	*error = LZMA_PROG_ERROR;
	if (f && blockSize && level) {
		LZMA_FILE *file = malloc(sizeof(LZMA_FILE));
		if (file) {
			file->f = f;
			file->buffer = malloc(blockSize);
			if (file->buffer) {
				file->bs = blockSize;
				
				memset(&file->strm, 0, sizeof(lzma_stream));
				*error = lzma_easy_encoder(&file->strm, level, LZMA_CHECK_CRC64);
				if (*error == LZMA_OK) {
					file->strm.next_out = file->buffer;
					file->strm.avail_out = blockSize;
					file->action = LZMA_RUN;
					return file;
				}
				free(file->buffer);
			}
			free(file);
		}
	}
	return NULL;
}

void lzma_xzWrite(lzma_ret *error, LZMA_FILE *file, const void *buf, size_t len) {
	if (file) {
		lzma_ret ret = LZMA_OK;
		file->strm.next_in = buf;
		file->strm.avail_in = len;
		while (ret != LZMA_STREAM_END) {
			file->strm.next_out = file->buffer;
			file->strm.avail_out = file->bs;
			ret = lzma_code(&file->strm, file->action);
			size_t write_size = file->bs - file->strm.avail_out;
			fwrite(file->buffer, 1, write_size, file->f);
			if (ret == LZMA_STREAM_END) break;
			else if (file->action == LZMA_FINISH) continue;
			if (ret != LZMA_OK) {
				*error = ret;
				break;
			}
			if (file->strm.avail_in == 0) break;
		}
		file->strm.next_in = NULL;
	} else {
		*error = LZMA_DATA_ERROR;
	}
}

void lzma_xzClose(lzma_ret *error, LZMA_FILE *file) {
	if (file) {
		file->action = LZMA_FINISH;
		lzma_xzWrite(error, file, NULL, 0);
		free(file->buffer);
		lzma_end(&file->strm);
		free(file);
	}
}
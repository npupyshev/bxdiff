/*
 * Copyright 2014-2016, Pupyshev Nikita. <npupyshev@icloud.com>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
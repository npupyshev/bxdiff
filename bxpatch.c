/*
 * Copyright 2014, Pupyshev Nikita. <npupyshev@icloud.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <lzma.h>
#include <openssl/sha.h>

typedef struct {
	uint64_t mixlen;
	uint64_t copylen;
	uint64_t seeklen;
} bxdiff_control_t;

typedef struct {
	char magic[8];
	uint64_t control_size;
	uint64_t diff_size;
	uint64_t patched_file_size;
} bxdiff_header_t;

FILE *in_file, *out_file;
int patch_file;

size_t in_file_size = 0;
size_t patch_file_length;

bxdiff_header_t header;
uint8_t sha[20];

void *control, *diff, *extra = NULL;
size_t extra_compressed_length;

static void *lzma_easy_buffer_decompress (void *compressed_data, size_t size, size_t *dsize);
static uint64_t parse_integer(uint64_t);
static void print_hex(const void *, size_t);
static int SHA1_File(FILE *, uint8_t *);

int main(int argc, const char * argv[]) {
    if (argc < 4) {
        puts("Usage: bxpatch <in_file> <out_file> <patch_file>");
        return 0;
    }
	
    patch_file = open(argv[3], O_RDONLY);
	if (patch_file < 0) {
		fprintf(stderr, "Failed to open %s.\n", argv[3]);
		exit(1);
	}
	
    patch_file_length = lseek(patch_file, 0, SEEK_END);
	if (patch_file_length <= sizeof(bxdiff_header_t)) {
		fprintf(stderr, "%s is not a BXDIFF40/BXDIFF41 patch.\n", argv[3]);
		close(patch_file);
		exit(1);
	}
    lseek(patch_file, 0, SEEK_SET);
	
	if (read(patch_file, &header, sizeof(header)) != sizeof(header)) {
		fprintf(stderr, "Unexpected I/O error.\n");
		close(patch_file);
		exit(1);
	}
	
	bool hasHash;
	if (!strncmp(header.magic, "BXDIFF40", 8)) {
		hasHash = false;
	} else if (!strncmp(header.magic, "BXDIFF41", 8)) {
		hasHash = true;
		if (read(patch_file, sha, SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH) {
			fprintf(stderr, "Failed to read SHA1 hash.");
			close(patch_file);
			exit(1);
		}
	} else {
		fprintf(stderr, "%s is not a BXDIFF40/BXDIFF41 patch.\n", argv[3]);
		close(patch_file);
		exit(1);
	}
	
	if (hasHash) {
		in_file = fopen(argv[1], "rb");
		if (!in_file) {
			fprintf(stderr, "Failed to open %s.", argv[1]);
			close(patch_file);
			exit(1);
		}
		
		void *actual_hash = alloca(SHA_DIGEST_LENGTH);
		if (SHA1_File(in_file, actual_hash)) {
			if (memcmp(sha, actual_hash, SHA_DIGEST_LENGTH) != 0) {
				printf("This patch can not be applied to the provided file (wrong SHA1 hash).\nDo you still want to continue?[n]: ");
				char c = getchar();
				if ((c != 'y') && (c != 'Y')) {
					fclose(in_file);
					close(patch_file);
					exit(1);
				}
			}
		}
		
		fclose(in_file);
	}
	
	size_t patch_length_no_extra = header.control_size + header.diff_size + SHA_DIGEST_LENGTH * hasHash + sizeof(bxdiff_header_t);
	if (patch_length_no_extra > patch_file_length) {
		fprintf(stderr, "Patch is truncated.\n");
		close(patch_file);
		exit(1);
	}
	extra_compressed_length = patch_file_length - patch_length_no_extra;
	
    control = malloc(header.control_size);
    diff = malloc(header.diff_size);
	if (!control || !diff) {
		fprintf(stderr, "Memory allocation error.\n");
		if (control) free(control);
		else if (diff) free(diff);
		close(patch_file);
		exit(1);
	}
	if (extra_compressed_length > 0) {
		extra = malloc(extra_compressed_length);
		if (!extra) {
			fprintf(stderr, "Memory allocation error.\n");
			free(control);
			free(diff);
			close(patch_file);
			exit(1);
		}
	}
	
	/* Reading all patch blocks. */
	if (read(patch_file, control, header.control_size) != header.control_size) {
		fprintf(stderr, "Failed to read control block.\n");
		goto patch_block_read_error;
	}
	if (read(patch_file, diff, header.diff_size) != header.diff_size) {
		fprintf(stderr, "Failed to read diff block.\n");
		goto patch_block_read_error;
	}
	if (extra) {
		if (read(patch_file, extra, extra_compressed_length) != extra_compressed_length) {
			fprintf(stderr, "Failed to read extra block.\n");
		patch_block_read_error:
			free(control);
			free(diff);
			if (extra) free(extra);
			close(patch_file);
			exit(1);
		}
	}
	
	close(patch_file);
	
	size_t control_length, diff_length, extra_length;
	
	void *buf;
	
    control_length = 0;
    buf = lzma_easy_buffer_decompress(control, (uint32_t)header.control_size, &control_length);
	free(control);
    if (!buf) {
        fprintf(stderr, "Failed to decompress control block.\n");
		free(diff);
		if (extra) free(extra);
		exit(1);
    }
	control = buf;
	
    diff_length = 0;
    buf = lzma_easy_buffer_decompress(diff, (uint32_t)header.diff_size, &diff_length);
	free(diff);
    if (!buf) {
		fprintf(stderr, "Failed to extract diff block.\n");
		free(control);
		if (extra) free(extra);
		exit(1);
    }
	diff = buf;
    
    if (extra) {
        buf = lzma_easy_buffer_decompress(extra, extra_compressed_length, &extra_length);
        if (!buf) {
			fprintf(stderr, "Failed to extract extra block.\n");
			free(control);
			free(diff);
			exit(1);
        }
		extra = buf;
    }
	
	in_file = fopen(argv[1], "rb");
	out_file = fopen(argv[2], "w+");
	ftruncate(fileno(out_file), 0);
	
	bxdiff_control_t *c = control;
	uint8_t *d = diff, *e = extra;
	uint64_t mixlen, copylen;
	int64_t seeklen;
	
    while (((void *)c - control) < control_length) {
        copylen = parse_integer(c->copylen);
        mixlen = parse_integer(c->mixlen);
        seeklen = parse_integer(c->seeklen);
        
        /* Read mixlen bytes from diff block and from the input file,
		 * add them modulo 256 and write that to the output file
		 */
		if (mixlen) {
			uint8_t *diff_block = malloc(mixlen);
			if (fread(diff_block, 1, mixlen, in_file) != mixlen) {
				fprintf(stderr, "Input file is truncated.\n");
				free(control);
				free(diff);
				if (extra) free(extra);
				fclose(in_file);
				fclose(out_file);
				exit(1);
			}
			for (uint64_t i = 0; i < mixlen; i++) {
				diff_block[i] = *d + diff_block[i];
				d++;
			}
			fwrite(diff_block, 1, mixlen, out_file);
			free(diff_block);
		}
		
        /* Copy copylen bytes from extra block to the output file */
		if (copylen) {
			fwrite(e, 1, copylen, out_file);
			e += copylen;
		}
		
        /* Advance the read pointer by seeklen bytes */
		if (seeklen)
			fseeko(in_file, seeklen, SEEK_CUR);
        
        /* Advance control block read pointer */
        c++;
    }

    free(control);
    free(diff);
    if (extra) free(extra);
	
	size_t expected_size = header.patched_file_size;
	size_t actual_size = ftello(out_file);
    if (expected_size != actual_size)
		printf("Expected size: %zu\nActual size:   %zu\n", expected_size, actual_size);
    fclose(in_file);
    fclose(out_file);
    
    return 0;
}

static void print_hex(const void *data, size_t length) {
	for (size_t i = 0; i < length; i++)
		printf("%02x", ((uint8_t *)data)[i]);
	putchar('\n');
}

static int SHA1_File(FILE *f, uint8_t *dst) {
	int ret = false;
	if (f && dst) {
		size_t bytes_read = 0;
		off_t pos = ftello(f);
		fseek(f, 0, SEEK_END);
		size_t length = ftello(f);
		fseek(f, 0, SEEK_SET);
		if (length) {
			SHA_CTX ctx;
			if (SHA1_Init(&ctx)) {
				void *buf = malloc(512);
				memset(buf, 0, 512);
				size_t bytes_available;
				
				while (bytes_read < length) {
					if ((bytes_available = fread(buf, 1, 512, f)) <= 0) {
						fseeko(f, pos, SEEK_SET);
						return false;
					}
					SHA1_Update(&ctx, buf, bytes_available);
					bytes_read += bytes_available;
				}
				
				SHA1_Final(dst, &ctx);
				ret = true;
			}
		}
		fseeko(f, pos, SEEK_SET);
	}
	
	return ret;
}

static uint64_t parse_integer(uint64_t integer)
{
    uint8_t *buf = (u_char *)&integer;
    uint64_t y;
    
    y = buf[7] & 0x7F;
    y <<= 8;
	y += buf[6];
	y <<= 8;
	y += buf[5];
	y <<= 8;
	y += buf[4];
	y <<= 8;
	y += buf[3];
	y <<= 8;
	y += buf[2];
	y <<= 8;
	y += buf[1];
	y <<= 8;
    y += buf[0];
    
    if (buf[7] & 0x80) y = -y;
    
    return y;
}

/* Frees compressed_data.
 * dsize is a pointer to a place where the size of decompressed file will be written.
 * Contains code from XZ tools.
 */

static void *lzma_easy_buffer_decompress(void *compressed_data, size_t size, size_t *dsize)
{
    lzma_stream strm = LZMA_STREAM_INIT; /* alloc and init lzma_stream struct */
    const uint32_t flags = LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED;
    const uint64_t memory_limit = UINT64_MAX; /* no memory limit */
    uint8_t out_buf[1024];
    size_t out_len;	/* length of useful data in out_buf */
    void *res = NULL;
    lzma_action action;
    lzma_ret ret_xz;
	*dsize = 0;
	
    /* initialize xz decoder */
    ret_xz = lzma_stream_decoder(&strm, memory_limit, flags);
    if (ret_xz != LZMA_OK) {
        fprintf(stderr, "lzma_stream_decoder error: %d\n", (int) ret_xz);
        return NULL;
    }
    
    strm.next_in = compressed_data;
    strm.avail_in = size;
    
    /* if no more data from in_buf, flushes the
     internal xz buffers and closes the decompressed data
     with LZMA_FINISH */
    action = LZMA_FINISH;
    
    /* loop until there's no pending decompressed output */
    do {
        /* out_buf is clean at this point */
        strm.next_out = out_buf;
        strm.avail_out = 1024;
        
        /* decompress data */
        ret_xz = lzma_code(&strm, action);
        
        if ((ret_xz != LZMA_OK) && (ret_xz != LZMA_STREAM_END)) {
            fprintf(stderr, "lzma_code error: %d\n", (int)ret_xz);
			lzma_end(&strm);
			if (res) free(res);
            return NULL;
        } else {
            /* write decompressed data */
            out_len = 1024 - strm.avail_out;
            *dsize += out_len;
            if (!res) res = malloc(out_len);
            else res = realloc(res, *dsize);
            memcpy(res + *dsize - out_len, out_buf, out_len);
        }
    } while (strm.avail_out == 0);
    
    lzma_end(&strm);
    return res;
}

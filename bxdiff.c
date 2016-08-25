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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <lzma.h>
#include <openssl/sha.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bswapLittleToHost32(x) x
#define bswapBigToHost32(x) __builtin_bswap32(x)
#define bswapHostToLittle32(x) x
#define bswapHostToBig32(x) __builtin_bswap32(x)
#define bswapLittleToHost64(x) x
#define bswapBigToHost64(x) __builtin_bswap64(x)
#define bswapHostToLittle64(x) x
#define bswapHostToBig64(x) __builtin_bswap64(x)
#else
#define bswapLittleToHost32(x) __builtin_bswap32(x)
#define bswapBigToHost32(x) x
#define bswapHostToLittle32(x) __builtin_bswap32(x)
#define bswapHostToBig32(x) x
#define bswapLittleToHost64(x) __builtin_bswap64(x)
#define bswapBigToHost64(x) x
#define bswapHostToLittle64(x) __builtin_bswap64(x)
#define bswapHostToBig64(x) x
#endif

typedef enum {
	BXDIFF_INVALID = 0,
	BXDIFF40 = 1,
	BXDIFF41 = 2,
	BXDIFF50 = 3,
} bxdiff_version_t;

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
} bxdiff40_header_t;

typedef struct __attribute__((packed)) {
	char magic[8];
	uint64_t unknown;
	uint64_t patched_file_size;
	uint64_t control_size;
	uint64_t extra_size;
	uint8_t result_sha1[20];
	uint64_t diff_size;
	uint8_t target_sha1[20];
}  bxdiff50_header_t;

FILE *in_file, *out_file;
int patch_file;
bool force = false;

size_t in_file_size = 0;
size_t patch_file_length;

bxdiff_version_t version;
size_t patched_file_size = 0;
void *control, *diff, *extra;
size_t control_length, diff_length, extra_length;

uint8_t input_sha1[20];
bool has_input_hash;
uint8_t output_sha1[20];
uint8_t target_output_sha1[20];
bool has_output_hash;

size_t extra_compressed_length;

static void *lzma_easy_buffer_decompress (void *compressed_data, size_t size, size_t *dsize);
static void *pbzx_buffer_decompress(void *compressed_data, size_t size, size_t *dsize, bool *empty);
static uint64_t parse_integer(uint64_t);
static void print_hex(const void *, size_t);
static int SHA1_File(FILE *, uint8_t *);

int main(int argc, const char * argv[]) {
	const char *infile_path = argv[1];
	const char *outfile_path = argv[2];
	const char *patchfile_path = argv[3];
	
	if ((argc != 4) && (argc != 5)) {
		puts("usage: bxpatch [-f] <oldfile> <newfile> <patchfile>");
		return 0;
	}
	if (argc == 5) {
		if (strcmp(argv[1], "-f")) {
			puts("usage: bxpatch [-f] <oldfile> <newfile> <patchfile>");
			return 0;
		} else {
			force = true;
			infile_path = argv[2];
			outfile_path = argv[3];
			patchfile_path = argv[4];
		}
	}
	
	patch_file = open(patchfile_path, O_RDONLY);
	if (patch_file < 0) {
		fprintf(stderr, "Failed to open %s.\n", patchfile_path);
		exit(1);
	}
	
	patch_file_length = lseek(patch_file, 0, SEEK_END);
	if (patch_file_length <= sizeof(bxdiff40_header_t)) {
		fprintf(stderr, "%s is not a BXDIFF patch.\n", patchfile_path);
		close(patch_file);
		exit(1);
	}
	lseek(patch_file, 0, SEEK_SET);
	
	char magic[8];
	if (read(patch_file, &magic, 8) != 8) {
		fprintf(stderr, "Unexpected I/O error.\n");
		close(patch_file);
		exit(1);
	}
	
	if (!strncmp(magic, "BXDIFF40", 8)) {
		version = BXDIFF40;
		has_input_hash = false;
		has_output_hash = false;
	} else if (!strncmp(magic, "BXDIFF41", 8)) {
		version = BXDIFF41;
		has_input_hash = true;
		has_output_hash = false;
	} else if (!strncmp(magic, "BXDIFF50", 8)) {
		version = BXDIFF50;
		has_input_hash = true;
		has_output_hash = true;
	} else if (!strncmp(magic, "BSDIFF", 6)) {
		fprintf(stderr, "BSDIFF patches are not supported.\n");
		close(patch_file);
		exit(1);
	} else {
		fprintf(stderr, "%s is not a BXDIFF patch.\n", patchfile_path);
		close(patch_file);
		exit(1);
	}
	
	in_file = fopen(infile_path, "rb");
	if (!in_file) {
		fprintf(stderr, "Failed to open %s.", infile_path);
		close(patch_file);
		exit(1);
	}
	fseek(in_file, 0, SEEK_END);
	in_file_size = ftell(in_file);
	fseek(in_file, 0, SEEK_SET);
	if (has_input_hash) {
		if (!SHA1_File(in_file, input_sha1)) {
			fprintf(stderr, "Failed to calculate SHA1 hash of the input file.\n");
			fclose(in_file);
			close(patch_file);
			exit(1);
		}
	}
	fclose(in_file);
	
	lseek(patch_file, 0, SEEK_SET);
	if (version < BXDIFF50) {
		bxdiff40_header_t header;
		if (read(patch_file, &header, sizeof(bxdiff40_header_t)) != sizeof(bxdiff40_header_t)) {
			fprintf(stderr, "Unexpected I/O error.\n");
			close(patch_file);
			exit(1);
		}
		
		if (has_input_hash) {
			void *actual_hash = alloca(SHA_DIGEST_LENGTH);
			if (read(patch_file, actual_hash, SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH) {
				fprintf(stderr, "Unexpected I/O error.\n");
				close(patch_file);
				exit(1);
			}
			
			if (memcmp(actual_hash, input_sha1, SHA_DIGEST_LENGTH)) {
				if (!force) {
					printf("This patch shall not be applied to the provided file (wrong SHA1 hash).\nDo you still want to continue? (y/n) [n]: ");
					char c = getchar();
					if ((c != 'y') && (c != 'Y')) {
						close(patch_file);
						exit(1);
					}
				} else {
					puts("SHA1 hash mismatch. Forcing patch anyway.");
				}
			}
		}
		
		patched_file_size = header.patched_file_size;
		size_t patch_length_no_extra = header.control_size + header.diff_size + SHA_DIGEST_LENGTH * has_input_hash + sizeof(bxdiff40_header_t);
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
			goto bxdiff40_block_read_error;
		}
		if (read(patch_file, diff, header.diff_size) != header.diff_size) {
			fprintf(stderr, "Failed to read diff block.\n");
			goto bxdiff40_block_read_error;
		}
		if (extra) {
			if (read(patch_file, extra, extra_compressed_length) != extra_compressed_length) {
				fprintf(stderr, "Failed to read extra block.\n");
			bxdiff40_block_read_error:
				free(control);
				free(diff);
				if (extra) free(extra);
				close(patch_file);
				exit(1);
			}
		}
		
		close(patch_file);
		
		void *buf;
		
		control_length = 0;
		buf = lzma_easy_buffer_decompress(control, (uint32_t)header.control_size, &control_length);
		free(control);
		if (!buf) {
			fprintf(stderr, "Failed to extract control block.\n");
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
			free(extra);
			if (!buf) {
				fprintf(stderr, "Failed to extract extra block.\n");
				free(control);
				free(diff);
				exit(1);
			}
			extra = buf;
		}
	} else if (version == BXDIFF50) {
		bxdiff50_header_t header;
		if (read(patch_file, &header, sizeof(bxdiff50_header_t)) != sizeof(bxdiff50_header_t)) {
			fprintf(stderr, "Unexpected I/O error.\n");
			close(patch_file);
			exit(1);
		}
		
		header.control_size = bswapLittleToHost64(header.control_size);
		header.diff_size = bswapLittleToHost64(header.diff_size);
		header.extra_size = bswapLittleToHost64(header.extra_size);
		header.patched_file_size = bswapLittleToHost64(header.patched_file_size);
		
		patched_file_size = header.patched_file_size;
		if ((header.control_size + header.diff_size + header.extra_size + sizeof(bxdiff50_header_t)) != patch_file_length) {
			fprintf(stderr, "Patch is corrupt.\n");
			close(patch_file);
			exit(1);
		}
		
		if (memcmp(header.target_sha1, input_sha1, SHA_DIGEST_LENGTH)) {
			if (!force) {
				printf("This patch shall not be applied to the provided file (wrong SHA1 hash).\nDo you still want to continue? (y/n) [n]: ");
				char c = getchar();
				if ((c != 'y') && (c != 'Y')) {
					close(patch_file);
					exit(1);
				}
			} else {
				puts("SHA1 hash mismatch. Forcing patch anyway.");
			}
		}
		memcpy(target_output_sha1, header.result_sha1, 20);
		
		control = malloc(header.control_size);
		diff = malloc(header.diff_size);
		extra = malloc(header.extra_size);
		if (!control || !diff || !extra) {
			fprintf(stderr, "Memory allocation error.\n");
			if (control) free(control);
			if (diff) free(diff);
			if (extra) free(extra);
			close(patch_file);
			exit(1);
		}
		
		/* Reading all patch blocks. */
		if (read(patch_file, control, header.control_size) != header.control_size) {
			fprintf(stderr, "Failed to read control block.\n");
			goto bxdiff50_block_read_error;
		}
		if (read(patch_file, diff, header.diff_size) != header.diff_size) {
			fprintf(stderr, "Failed to read diff block.\n");
			goto bxdiff50_block_read_error;
		}
		if (read(patch_file, extra, header.extra_size) != header.extra_size) {
			fprintf(stderr, "Failed to read extra block.\n");
		bxdiff50_block_read_error:
			free(control);
			free(diff);
			if (extra) free(extra);
			close(patch_file);
			exit(1);
		}
		
		close(patch_file);
		
		void *buf;
		bool empty = false;
		
		control_length = 0;
		buf = pbzx_buffer_decompress(control, header.control_size, &control_length, &empty);
		free(control);
		if (!buf) {
			if (!empty) fprintf(stderr, "Failed to extract control block.\n");
			else fprintf(stderr, "Patch is corrupt (empty control block).\n");
			free(diff);
			if (extra) free(extra);
			exit(1);
		}
		control = buf;
		
		diff_length = 0;
		buf = pbzx_buffer_decompress(diff, (uint32_t)header.diff_size, &diff_length, &empty);
		free(diff);
		if (!buf) {
			if (!empty) fprintf(stderr, "Failed to extract diff block.\n");
			else fprintf(stderr, "Patch is corrupt (empty diff block).");
			free(control);
			if (extra) free(extra);
			exit(1);
		}
		diff = buf;
		
		if (extra) {
			buf = pbzx_buffer_decompress(extra, header.extra_size, &extra_length, &empty);
			free(extra);
			if (!(buf || empty)) {
				fprintf(stderr, "Failed to extract extra block.\n");
				free(control);
				free(diff);
				exit(1);
			}
			extra = buf;
		}
	}
	
	in_file = fopen(infile_path, "rb");
	out_file = fopen(outfile_path, "w+");
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
			if (!extra) {
				fprintf(stderr, "Patch is corrupt.\n");
				free(control);
				free(diff);
				if (extra) free(extra);
				fclose(in_file);
				fclose(out_file);
				exit(1);
			}
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
	
	size_t expected_size = patched_file_size;
	size_t actual_size = ftello(out_file);
	if (expected_size != actual_size)
		printf("Expected size: %zu\nActual size:   %zu\n", expected_size, actual_size);
	
	if (has_output_hash) {
		if (!SHA1_File(out_file, output_sha1)) {
			fprintf(stderr, "Failed to calculate SHA1 hash of the input file.\n");
		} else if (memcmp(target_output_sha1, output_sha1, 20)) {
			fprintf(stderr, "Output file is corrupt (SHA1 hash mismatch).\n");
		}
	}
	
	fclose(in_file);
	fclose(out_file);
	
	return 0;
}

#ifdef DEBUG

static void __attribute__((unused)) print_hex(const void *data, size_t length) {
	for (size_t i = 0; i < length; i++)
		printf("%02x", ((uint8_t *)data)[i]);
	putchar('\n');
}

#endif

static int SHA1_File(FILE *f, uint8_t *dst) {
	int ret = false;
	if (f && dst) {
		size_t bytes_read = 0;
		off_t pos = ftello(f);
		fseek(f, 0, SEEK_END);
		size_t length = ftello(f);
		fseek(f, 0, SEEK_SET);
		
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

/*
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

/*
 * That code definitely needs to be fixed.
 */
static void *pbzx_buffer_decompress(void *compressed_data, size_t size, size_t *dsize, bool *empty) {
	if (size == 12) *empty = 1;//todo fix
	if (size > 20) {
		if (memcmp(compressed_data, "pbzx", 4)) return NULL;
		compressed_data += 4;
		size -= 4;
		uint64_t __attribute((unused)) flags = bswapBigToHost64(*(uint64_t *)compressed_data);
		compressed_data += 8;
		size -= 8;
		uint64_t uncompressed_size = bswapBigToHost64(*(uint64_t *)compressed_data);
		compressed_data += 8;
		size -= 8;
		if (!uncompressed_size) {
			if (empty) *empty = true;
			*dsize = 0;
			return NULL;
		} else {
			if (empty) *empty = false;
		}
		
		void *buf = malloc(uncompressed_size);
		if (buf) {
			lzma_stream strm = LZMA_STREAM_INIT; /* alloc and init lzma_stream struct */
			const uint32_t lzma_flags = LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED;
			const uint64_t memory_limit = UINT64_MAX; /* no memory limit */
			lzma_action action = LZMA_RUN;
			lzma_ret ret_xz;
			*dsize = uncompressed_size;
			
			/* initialize xz decoder */
			ret_xz = lzma_stream_decoder(&strm, memory_limit, lzma_flags);
			if (ret_xz != LZMA_OK) {
				fprintf(stderr, "lzma_stream_decoder error: %d\n", (int) ret_xz);
				return NULL;
			}
			
			void *p = buf;
			uint64_t chunk_length;
			bool first_chunk = true;
			while (size) {
				if (size < 8 + !first_chunk * 8) {
					fprintf(stderr, "Patch is truncated.\n");
					free(buf);
					lzma_end(&strm);
					return NULL;
				}
				
				//read flags if needed
				if (!first_chunk) {
					flags = bswapBigToHost64(*(uint64_t *)compressed_data);
					compressed_data += 8;
					size -= 8;
				} else {
					first_chunk = false;
				}
				
				chunk_length = bswapBigToHost64(*(uint64_t *)compressed_data);
				compressed_data += 8;
				size -= 8;
				if (size < chunk_length) {
					fprintf(stderr, "Patch is truncated.\n");
					free(buf);
					lzma_end(&strm);
					return NULL;
				}
				
				//detect raw data
				if (memcmp(compressed_data, "\xFD""7zXZ\0\0", 8)) {
					memcpy(p, compressed_data, chunk_length);
					p += chunk_length;
					uncompressed_size -= chunk_length;
					compressed_data += chunk_length;
					size -= chunk_length;
					continue;
				}
				
				//finish on end
				if (size == chunk_length) {
					action = LZMA_FINISH;
				}
				
				strm.next_in = compressed_data;
				strm.avail_in = chunk_length;
				strm.next_out = p;
				strm.avail_out = uncompressed_size;
				
				ret_xz = lzma_code(&strm, action);
				
				if ((ret_xz != LZMA_OK) && (ret_xz != LZMA_STREAM_END)) {
					fprintf(stderr, "lzma_code error: %d\n", (int)ret_xz);
					lzma_end(&strm);
					free(buf);
					return NULL;
				} else {
					size_t out_len = uncompressed_size - strm.avail_out;
					p += out_len;
					uncompressed_size = strm.avail_out;
					compressed_data += chunk_length;
					size -= chunk_length;
				}
			};
			
			lzma_end(&strm);
			return buf;
		}
	}
	return NULL;
}

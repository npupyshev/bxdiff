/*
 * Copyright 2014, Pupyshev Nikita. <npupyshev@icloud.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * $Id$
 */

#include <stdio.h>
#include <lzma.h>
#include <stdlib.h>
#include <string.h>
#include "bxdiff.h"

void *decompress (void *compressed_data, size_t size, size_t *dsize);
static int64_t parse_integer(uint64_t integer);

FILE *in_file;
size_t in_file_size = 0;
FILE *out_file;
FILE *patch_file;
size_t patch_file_size;

void *control_block, *diff_block, *extra_block = NULL;
size_t control_block_size, diff_block_size, extra_block_size = 0;

int main(int argc, const char * argv[]) {
    if (argc < 4) {
        puts("Usage: bxdiff <in_file> <out_file> <patch_file>");
        return 0;
    }
    
    //  Get ready
    
    in_file = fopen(argv[1], "rb");
    out_file = fopen(argv[2], "wb");
    patch_file = fopen(argv[3], "rb");
    BXDIFFHeaderRef header = (BXDIFFHeaderRef)alloca(BXDIFF_HEADER_LENGTH);
    size_t extra_compressed_size = 0;
    size_t control_block_pointer = 0, diff_block_pointer = 0, extra_block_pointer = 0;
    
    //  Get patch file size
    
    fseek(patch_file, 0, SEEK_END);
    patch_file_size = ftell(patch_file);
    fseek(patch_file, 0, SEEK_SET);
    
    //  Read header, calculate sizes and allocate memory
    
    fread(header, BXDIFF_HEADER_LENGTH, 1, patch_file);
    control_block = (void *)malloc((uint32_t)header->control_size);
    diff_block = (void *)malloc((uint32_t)header->diff_size);
    extra_compressed_size = patch_file_size - (uint32_t)(header->control_size + header->diff_size) - BXDIFF_HEADER_LENGTH;
    //  TODO: Replace 0 with minimum archive size.
    if (extra_compressed_size > 0)
        extra_block = (void *)malloc(extra_compressed_size);
    
    //  Extract control block
    
    fread(control_block, (uint32_t)header->control_size, 1, patch_file);
    control_block_size = 0;
    control_block = decompress(control_block, (uint32_t)header->control_size, &control_block_size);
    if (!control_block) {
        puts("Failed to extract control block");
        return 1;
    }
    
    //  Extract diff block
    
    fread(diff_block, (uint32_t)header->diff_size, 1, patch_file);
    diff_block_size = 0;
    diff_block = decompress(diff_block, (uint32_t)header->diff_size, &diff_block_size);
    if (!diff_block) {
        puts("Failed to extract diff block");
        return -1;
    }
    
    //  Extract extra block if needed
    
    if (extra_block) {
        fread(extra_block, extra_compressed_size, 1, patch_file);
        extra_block = decompress(extra_block, extra_compressed_size, &extra_block_size);
        if (!extra_block) {
            puts("Failed to extract extra block");
            return -1;
        }
    }
    
    //  Close patch file
    
    fclose(patch_file);
    
    //  Patch file
    
    fseek(in_file, 0, SEEK_SET);
    fseek(out_file, 0, SEEK_SET);
    while (control_block_pointer < control_block_size) {
        //Yes, I like typedefing structs:)
        BXTriple *triple = (control_block + control_block_pointer);
        int64_t copylen = parse_integer(triple->copylen);
        int64_t mixlen = parse_integer(triple->mixlen);
        int64_t seeklen = parse_integer(triple->seeklen);
        uint8_t file_byte = 0;
        uint8_t out_byte;
        printf("%llu %llu %llu\n", mixlen, copylen, seeklen);
        
        //Read mixlen bytes from diff block and from the input file, add them modulo 256 and write that to th output file
        for (uint64_t i = 0; i < mixlen; i++) {
            fread(&file_byte, 1, 1, in_file);
            out_byte = (*(uint8_t *)(diff_block + diff_block_pointer) + file_byte) % 256;
            fwrite(&out_byte, 1, 1, out_file);
            diff_block_pointer++;
        }
        
        //Copy copylen bytes from extra block to the output file
        fwrite(extra_block + extra_block_pointer, (uint32_t)copylen, 1, out_file);
        extra_block_pointer += copylen;
        
        //Advance the read pointer by seeklen bytes
        fseek(in_file, (int32_t)seeklen, SEEK_CUR);
        
        //Advance control block read pointer
        control_block_pointer += sizeof(BXTriple);
    }
    
    free(control_block);
    free(diff_block);
    if (extra_block) free(extra_block);
    printf("File size: %lu\nExpected size: %llu\n", ftell(out_file), header->patched_file_size);
    fclose(out_file);
    fclose(in_file);
    
    return 0;
}

//Parses integer. Integer is stored in a weird format:
//  1. Little-endian
//  2. Sign-magnitude

static uint64_t parse_integer(uint64_t integer)
{
    uint8_t *buf = (u_char *)&integer;
    uint64_t y;
    
    y = buf[7] & 0x7F;
    y *= 256;
    y += buf[6];
    y *= 256;
    y += buf[5];
    y *= 256;
    y += buf[4];
    y *=256;
    y += buf[3];
    y *= 256;
    y += buf[2];
    y *= 256;
    y += buf[1];
    y *= 256;
    y += buf[0];
    
    if (buf[7] & 0x80) y = -y;
    
    return y;
}

//Frees compressed_data.
//dsize is a pointer to a place where the size of decompressed file will be written
//Contains code from XZ tools.

void *decompress (void *compressed_data, size_t size, size_t *dsize)
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
    ret_xz = lzma_stream_decoder (&strm, memory_limit, flags);
    if (ret_xz != LZMA_OK) {
        fprintf (stderr, "lzma_stream_decoder error: %d\n", (int) ret_xz);
        free(compressed_data);
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
        ret_xz = lzma_code (&strm, action);
        
        if ((ret_xz != LZMA_OK) && (ret_xz != LZMA_STREAM_END)) {
            fprintf (stderr, "lzma_code error: %d\n", (int) ret_xz);
            free(compressed_data);
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
    
    lzma_end (&strm);
    free(compressed_data);
    return res;
}

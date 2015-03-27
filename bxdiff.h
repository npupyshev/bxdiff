#ifndef bxdiff_h
#define bxdiff_h
#include <sys/types.h>
#define BXDIFF_HEADER_LENGTH sizeof(bxdiff_header)

typedef struct __attribute__((packed)) {
    const char magic[8];
    uint64_t control_size;
    uint64_t diff_size;
    uint64_t patched_file_size;
    uint8_t sha1[20];
} bxdiff_header;
typedef bxdiff_header* BXDIFFHeaderRef;

typedef struct {
    uint64_t mixlen;
    uint64_t copylen;
    uint64_t seeklen;
} BXTriple;

#endif

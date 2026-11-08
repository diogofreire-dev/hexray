// SHA-256, written from the specification (FIPS 180-4).
//
// The data arrives in pieces, so a file of any size can be hashed without loading it
// all into memory: call sha256_init once, sha256_update as often as needed, and
// sha256_final once at the end.

#ifndef HEXRAY_SHA256_H
#define HEXRAY_SHA256_H

#include <stddef.h>
#include <stdint.h>   // types with an exact size: uint32_t is always 32 bits

#define SHA256_DIGEST_SIZE 32   // the result, in bytes (256 bits)
#define SHA256_BLOCK_SIZE 64    // the algorithm works on blocks of 512 bits

typedef struct
{
    uint32_t state[8];                         // the hash so far
    uint64_t total_bytes;                      // how much data has been given to us
    unsigned char block[SHA256_BLOCK_SIZE];    // data waiting for a full block
    size_t used;                               // how many bytes of `block` are filled
} Sha256;

void sha256_init(Sha256 *sha);
void sha256_update(Sha256 *sha, const void *data, size_t length);
void sha256_final(Sha256 *sha, unsigned char digest[SHA256_DIGEST_SIZE]);

#endif

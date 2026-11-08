// SHA-256, written from the specification (FIPS 180-4).
//
// The idea: 8 numbers of 32 bits start with fixed values, and every 64-byte block of
// the data stirs them through 64 rounds of bit operations. Those 8 numbers at the end
// are the hash. Change one bit of the input and about half of the output bits change.
//
// Every addition here is meant to overflow. For unsigned types C defines exactly what
// happens: the result wraps around modulo 2^32, which is what SHA-256 asks for. With
// signed integers the same overflow would be undefined behaviour.

#include "sha256.h"

#include <string.h>

// Fixed by the standard: the first 32 bits of the fractional parts of the cube roots
// of the first 64 prime numbers. Using numbers anyone can recompute shows that nobody
// picked them to hide a weakness.
static const uint32_t round_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// Rotate right: the bits pushed off the right end come back in on the left.
// C has no operator for this, so it is built from two shifts.
static uint32_t rotr(uint32_t value, int bits)
{
    return (value >> bits) | (value << (32 - bits));
}

// Reads 4 bytes as a big-endian number (see the same idea in type.c)
static uint32_t read_be32(const unsigned char *bytes)
{
    return (uint32_t) bytes[0] << 24 | (uint32_t) bytes[1] << 16 |
           (uint32_t) bytes[2] << 8 | (uint32_t) bytes[3];
}

static void write_be32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char) (value >> 24);
    bytes[1] = (unsigned char) (value >> 16);
    bytes[2] = (unsigned char) (value >> 8);
    bytes[3] = (unsigned char) value;
}

// Mixes one 64-byte block into the state
static void compress(Sha256 *sha)
{
    // The message schedule: the block's 16 words, stretched to one word per round
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = read_be32(sha->block + i * 4);
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = sha->state[0];
    uint32_t b = sha->state[1];
    uint32_t c = sha->state[2];
    uint32_t d = sha->state[3];
    uint32_t e = sha->state[4];
    uint32_t f = sha->state[5];
    uint32_t g = sha->state[6];
    uint32_t h = sha->state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);              // each bit of e picks f or g
        uint32_t temp1 = h + sum1 + choose + round_constants[i] + w[i];
        uint32_t sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);   // each bit: what most of a, b, c say
        uint32_t temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Adding the old state back is what makes the function impossible to run backwards
    sha->state[0] += a;
    sha->state[1] += b;
    sha->state[2] += c;
    sha->state[3] += d;
    sha->state[4] += e;
    sha->state[5] += f;
    sha->state[6] += g;
    sha->state[7] += h;
}

void sha256_init(Sha256 *sha)
{
    // The first 32 bits of the fractional parts of the square roots of the first 8 primes
    static const uint32_t initial_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    memcpy(sha->state, initial_state, sizeof(sha->state));
    sha->total_bytes = 0;
    sha->used = 0;
}

// `const void *` accepts a pointer to anything. To move through it byte by byte we
// first have to say that we see it as bytes.
void sha256_update(Sha256 *sha, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    sha->total_bytes += length;

    while (length > 0)
    {
        size_t space = SHA256_BLOCK_SIZE - sha->used;
        size_t take = length < space ? length : space;

        memcpy(sha->block + sha->used, bytes, take);
        sha->used += take;
        bytes += take;
        length -= take;

        if (sha->used == SHA256_BLOCK_SIZE)
        {
            compress(sha);
            sha->used = 0;
        }
    }
}

// Padding fills the last block: a single 1 bit (the byte 0x80), then zeros, and the
// data's length in bits in the final 8 bytes. If the length does not fit in what is
// left of the block, the padding spills into one more block.
void sha256_final(Sha256 *sha, unsigned char digest[SHA256_DIGEST_SIZE])
{
    enum { LENGTH_FIELD_START = SHA256_BLOCK_SIZE - 8 };

    uint64_t total_bits = sha->total_bytes * 8;

    sha->block[sha->used++] = 0x80;   // room is guaranteed: update empties a full block

    if (sha->used > LENGTH_FIELD_START)
    {
        memset(sha->block + sha->used, 0, SHA256_BLOCK_SIZE - sha->used);
        compress(sha);
        sha->used = 0;
    }
    memset(sha->block + sha->used, 0, LENGTH_FIELD_START - sha->used);

    write_be32(sha->block + LENGTH_FIELD_START, (uint32_t) (total_bits >> 32));
    write_be32(sha->block + LENGTH_FIELD_START + 4, (uint32_t) total_bits);
    compress(sha);

    for (int i = 0; i < 8; i++)
    {
        write_be32(digest + i * 4, sha->state[i]);
    }
}

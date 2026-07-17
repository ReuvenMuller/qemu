#ifdef LLMOPT_STANDALONE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif

#include "llmopt-variants.h"

static inline uint32_t rotl32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32 - count));
}

static inline uint32_t rotr32(uint32_t value, unsigned count)
{
    return (value >> count) | (value << (32 - count));
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t load_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_portable(uint32_t state[4], const uint8_t block[64])
{
    uint32_t words[16];
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    for (size_t i = 0; i < 16; i++) {
        words[i] = load_le32(block + i * 4);
    }
    for (size_t i = 0; i < 64; i++) {
        uint32_t f, g, saved_d;
        if (i < 16) {
            f = (b & c) | (~b & d); g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c); g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d; g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d); g = (7 * i) % 16;
        }
        saved_d = d; d = c; c = b;
        b += rotl32(a + f + md5_k[i] + words[g], md5_s[i]);
        a = saved_d;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_portable(uint32_t state[8], const uint8_t block[64])
{
    uint32_t words[64];
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (size_t i = 0; i < 16; i++) {
        words[i] = load_be32(block + i * 4);
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(words[i - 15], 7) ^
                      rotr32(words[i - 15], 18) ^ (words[i - 15] >> 3);
        uint32_t s1 = rotr32(words[i - 2], 17) ^
                      rotr32(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    for (size_t i = 0; i < 64; i++) {
        uint32_t sum1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temp1 = h + sum1 + choice + sha256_k[i] + words[i];
        uint32_t sum0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

#if defined(__x86_64__)
extern void ossl_md5_block_asm_data_order(uint32_t state[4],
                                           const uint8_t *input,
                                           size_t blocks);
extern void sha256_multi_block(void *ctx, void *inputs, int groups);

/* The catalog requires only the base SSSE3 path; SHA-NI is not simulated. */
__attribute__((visibility("hidden")))
uint32_t OPENSSL_ia32cap_P[4] = { 0, 0, 0, 0 };

typedef struct Sha256MbInput {
    const uint8_t *pointer;
    int blocks;
    int padding;
} Sha256MbInput;

static bool sha256_optimized(uint32_t state[8], const uint8_t *input,
                             size_t blocks)
{
    uint32_t lanes[8][8] = { 0 };
    Sha256MbInput inputs[4];

    if (blocks > INT32_MAX) {
        return false;
    }
    for (size_t word = 0; word < 8; word++) {
        for (size_t lane = 0; lane < 4; lane++) {
            lanes[word][lane] = state[word];
        }
    }
    for (size_t lane = 0; lane < 4; lane++) {
        inputs[lane].pointer = input;
        inputs[lane].blocks = (int)blocks;
        inputs[lane].padding = 0;
    }
    sha256_multi_block(lanes, inputs, 1);
    for (size_t word = 0; word < 8; word++) {
        state[word] = lanes[word][0];
    }
    return true;
}
#endif

bool llmopt_variant_available(LlmoptHostVariant variant, bool sha256)
{
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        return true;
    }
#if defined(__x86_64__)
    __builtin_cpu_init();
    return sha256 ? __builtin_cpu_supports("ssse3") :
                    __builtin_cpu_supports("sse2");
#else
    return false;
#endif
}

bool llmopt_variant_md5(unsigned variant, uint32_t state[4],
                        const uint8_t *input, size_t blocks)
{
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
#if defined(__x86_64__)
        if (!llmopt_variant_available(variant, false)) {
            return false;
        }
        ossl_md5_block_asm_data_order(state, input, blocks);
        return true;
#else
        return false;
#endif
    }
    if (variant != LLMOPT_VARIANT_PORTABLE_C) {
        return false;
    }
    for (size_t block = 0; block < blocks; block++) {
        md5_portable(state, input + block * 64);
    }
    return true;
}

bool llmopt_variant_sha256(unsigned variant, uint32_t state[8],
                           const uint8_t *input, size_t blocks)
{
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
#if defined(__x86_64__)
        if (!llmopt_variant_available(variant, true)) {
            return false;
        }
        return sha256_optimized(state, input, blocks);
#else
        return false;
#endif
    }
    if (variant != LLMOPT_VARIANT_PORTABLE_C) {
        return false;
    }
    for (size_t block = 0; block < blocks; block++) {
        sha256_portable(state, input + block * 64);
    }
    return true;
}

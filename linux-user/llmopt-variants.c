#ifdef LLMOPT_STANDALONE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif

#include "llmopt-variants.h"

#include <math.h>

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

static inline uint64_t rotl64(uint64_t value, unsigned count)
{
    return (value << count) | (value >> (64 - count));
}

static inline uint64_t load_le64(const uint8_t *p)
{
    return (uint64_t)load_le32(p) | (uint64_t)load_le32(p + 4) << 32;
}

static inline uint64_t scalar_xxh64_round(uint64_t acc, uint64_t lane)
{
    return rotl64(acc + lane * UINT64_C(14029467366897019727), 31) *
           UINT64_C(11400714785074694791);
}

static inline __attribute__((always_inline))
uint64_t scalar_xxh64_body(const uint8_t *data, size_t length, uint64_t seed)
{
    const uint64_t p1 = UINT64_C(11400714785074694791);
    const uint64_t p2 = UINT64_C(14029467366897019727);
    const uint64_t p3 = UINT64_C(1609587929392839161);
    const uint64_t p4 = UINT64_C(9650029242287828579);
    const uint64_t p5 = UINT64_C(2870177450012600261);
    const uint8_t *p = data, *end = data + length;
    uint64_t hash;

    if (length >= 32) {
        uint64_t v1 = seed + p1 + p2, v2 = seed + p2;
        uint64_t v3 = seed, v4 = seed - p1;
        const uint8_t *limit = end - 32;
        do {
            v1 = scalar_xxh64_round(v1, load_le64(p)); p += 8;
            v2 = scalar_xxh64_round(v2, load_le64(p)); p += 8;
            v3 = scalar_xxh64_round(v3, load_le64(p)); p += 8;
            v4 = scalar_xxh64_round(v4, load_le64(p)); p += 8;
        } while (p <= limit);
        hash = rotl64(v1, 1) + rotl64(v2, 7) +
               rotl64(v3, 12) + rotl64(v4, 18);
        v1 = scalar_xxh64_round(0, v1); hash = (hash ^ v1) * p1 + p4;
        v2 = scalar_xxh64_round(0, v2); hash = (hash ^ v2) * p1 + p4;
        v3 = scalar_xxh64_round(0, v3); hash = (hash ^ v3) * p1 + p4;
        v4 = scalar_xxh64_round(0, v4); hash = (hash ^ v4) * p1 + p4;
    } else {
        hash = seed + p5;
    }
    hash += length;
    while (p + 8 <= end) {
        uint64_t lane = scalar_xxh64_round(0, load_le64(p));
        hash = rotl64(hash ^ lane, 27) * p1 + p4; p += 8;
    }
    if (p + 4 <= end) {
        hash = rotl64(hash ^ (uint64_t)load_le32(p) * p1, 23) * p2 + p3;
        p += 4;
    }
    while (p < end) {
        hash = rotl64(hash ^ (uint64_t)*p++ * p5, 11) * p1;
    }
    hash ^= hash >> 33; hash *= p2;
    hash ^= hash >> 29; hash *= p3;
    hash ^= hash >> 32;
    return hash;
}

static inline __attribute__((always_inline))
uint32_t scalar_crc32_body(const uint8_t *data, size_t length, uint32_t initial)
{
    uint32_t crc = initial ^ UINT32_C(0xffffffff);
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0U - (crc & 1U)));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static inline __attribute__((always_inline))
uint32_t scalar_adler32_body(const uint8_t *data, size_t length,
                             uint32_t initial)
{
    uint32_t s1 = initial & 0xffffU, s2 = initial >> 16;
    for (size_t i = 0; i < length; i++) {
        s1 += data[i];
        if (s1 >= 65521U) {
            s1 -= 65521U;
        }
        s2 += s1;
        if (s2 >= 65521U) {
            s2 -= 65521U;
        }
    }
    return s2 << 16 | s1;
}

static __attribute__((noinline)) uint64_t
xxh64_portable(const uint8_t *input, size_t length, uint64_t seed)
{
    return scalar_xxh64_body(input, length, seed);
}

static __attribute__((noinline)) uint32_t
crc32_portable(const uint8_t *input, size_t length, uint32_t initial)
{
    return scalar_crc32_body(input, length, initial);
}

static __attribute__((noinline)) uint32_t
adler32_portable(const uint8_t *input, size_t length, uint32_t initial)
{
    return scalar_adler32_body(input, length, initial);
}

#if defined(__x86_64__)
static __attribute__((target("avx2"), noinline)) uint64_t
xxh64_optimized(const uint8_t *input, size_t length, uint64_t seed)
{
    return scalar_xxh64_body(input, length, seed);
}

static __attribute__((target("avx2"), noinline)) uint32_t
crc32_optimized(const uint8_t *input, size_t length, uint32_t initial)
{
    return scalar_crc32_body(input, length, initial);
}

static __attribute__((target("avx2"), noinline)) uint32_t
adler32_optimized(const uint8_t *input, size_t length, uint32_t initial)
{
    return scalar_adler32_body(input, length, initial);
}
#endif

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

bool llmopt_variant_available(LlmoptHostVariant variant,
                              LlmoptVariantAlgorithm algorithm)
{
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        return true;
    }
#if defined(__x86_64__)
    __builtin_cpu_init();
    if (algorithm == LLMOPT_VARIANT_ALGO_SHA256) {
        return __builtin_cpu_supports("ssse3");
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_MD5) {
        return __builtin_cpu_supports("sse2");
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_LZ_MATCH_COPY) {
        return true;
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_MEMSET) {
        return true;
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_XXH64_STREAM) {
        return variant == LLMOPT_VARIANT_PORTABLE_C ||
               __builtin_cpu_supports("avx2");
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_SHA256_STREAM) {
        return variant == LLMOPT_VARIANT_PORTABLE_C ||
               __builtin_cpu_supports("avx2");
    }
    if (algorithm == LLMOPT_VARIANT_ALGO_FP_SAMPLERATE) {
        return __builtin_cpu_supports("fma");
    }
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

bool llmopt_variant_md5(unsigned variant, uint32_t state[4],
                        const uint8_t *input, size_t blocks)
{
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
#if defined(__x86_64__)
        if (!llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_MD5)) {
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
        if (!llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_SHA256)) {
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

bool llmopt_variant_xxh64(unsigned variant, const uint8_t *input,
                          size_t length, uint64_t seed, uint64_t *result)
{
    if (!result || !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_XXH64)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        *result = xxh64_portable(input, length, seed);
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        *result = xxh64_optimized(input, length, seed);
        return true;
    }
#endif
    return false;
}

bool llmopt_variant_crc32(unsigned variant, const uint8_t *input,
                          size_t length, uint32_t initial, uint32_t *result)
{
    if (!result || !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_CRC32)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        *result = crc32_portable(input, length, initial);
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        *result = crc32_optimized(input, length, initial);
        return true;
    }
#endif
    return false;
}

bool llmopt_variant_adler32(unsigned variant, const uint8_t *input,
                            size_t length, uint32_t initial, uint32_t *result)
{
    if (!result || !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_ADLER32)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        *result = adler32_portable(input, length, initial);
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        *result = adler32_optimized(input, length, initial);
        return true;
    }
#endif
    return false;
}

__attribute__((noinline, optimize("no-tree-loop-distribute-patterns")))
static void memcpy_portable(uint8_t *destination, const uint8_t *source,
                            size_t length)
{
    while (length--) {
        *destination++ = *source++;
    }
}

__attribute__((target("avx2"), noinline))
static void memcpy_optimized(uint8_t *destination, const uint8_t *source,
                             size_t length)
{
    memcpy(destination, source, length);
}

bool llmopt_variant_memcpy(unsigned variant, uint8_t *destination,
                           const uint8_t *source, size_t length)
{
    if (!llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_MEMCPY)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        memcpy_portable(destination, source, length);
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        memcpy_optimized(destination, source, length);
        return true;
    }
#endif
    return false;
}

__attribute__((noinline, optimize("no-tree-loop-distribute-patterns")))
static void lz_match_copy_portable(uint8_t *output, size_t length,
                                   size_t distance)
{
    uint8_t *source = output - distance;
    while (length--) {
        *output++ = *source++;
    }
}

__attribute__((noinline, optimize("no-tree-loop-distribute-patterns")))
static void lz_match_copy_optimized(uint8_t *output, size_t length,
                                    size_t distance)
{
    uint8_t *source = output - distance;
    while (length >= 8 && distance >= 8) {
        output[0] = source[0]; output[1] = source[1];
        output[2] = source[2]; output[3] = source[3];
        output[4] = source[4]; output[5] = source[5];
        output[6] = source[6]; output[7] = source[7];
        output += 8; source += 8; length -= 8;
    }
    while (length--) {
        *output++ = *source++;
    }
}

bool llmopt_variant_lz_match_copy(unsigned variant, uint8_t *output,
                                  size_t length, size_t distance)
{
    if (!output || !distance ||
        !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_LZ_MATCH_COPY)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        lz_match_copy_portable(output, length, distance);
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        lz_match_copy_optimized(output, length, distance);
        return true;
    }
#endif
    return false;
}

bool llmopt_variant_memset(unsigned variant, uint8_t *output,
                           uint8_t value, size_t length)
{
    if (!output ||
        !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_MEMSET)) {
        return false;
    }
    if (variant == LLMOPT_VARIANT_PORTABLE_C) {
        while (length--) {
            *output++ = value;
        }
        return true;
    }
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        memset(output, value, length);
        return true;
    }
#endif
    return false;
}

typedef struct LlmoptXxh64StreamingState {
    uint64_t total_len;
    uint64_t v[4];
    uint8_t buffer[32];
    uint32_t memsize;
    uint32_t reserved32;
    uint64_t reserved64;
} LlmoptXxh64StreamingState;

_Static_assert(sizeof(LlmoptXxh64StreamingState) == 88,
               "pinned XXH64 streaming state layout");

static void xxh64_stream_stripe(LlmoptXxh64StreamingState *state,
                                const uint8_t *input)
{
    state->v[0] = scalar_xxh64_round(state->v[0], load_le64(input));
    state->v[1] = scalar_xxh64_round(state->v[1], load_le64(input + 8));
    state->v[2] = scalar_xxh64_round(state->v[2], load_le64(input + 16));
    state->v[3] = scalar_xxh64_round(state->v[3], load_le64(input + 24));
}

static bool xxh64_stream_update(LlmoptXxh64StreamingState *state,
                                const uint8_t *input, size_t length)
{
    const uint8_t *current = input;
    const uint8_t *end;

    if (!input) {
        return length == 0;
    }
    end = input + length;
    state->total_len += length;
    if (state->memsize + length < 32) {
        memcpy(state->buffer + state->memsize, input, length);
        state->memsize += length;
        return true;
    }
    if (state->memsize) {
        size_t fill = 32 - state->memsize;
        memcpy(state->buffer + state->memsize, current, fill);
        xxh64_stream_stripe(state, state->buffer);
        current += fill;
        state->memsize = 0;
    }
    if (current + 32 <= end) {
        const uint8_t *limit = end - 32;
        do {
            xxh64_stream_stripe(state, current);
            current += 32;
        } while (current <= limit);
    }
    if (current < end) {
        size_t tail = end - current;
        memcpy(state->buffer, current, tail);
        state->memsize = tail;
    }
    return true;
}

bool llmopt_variant_xxh64_stream(unsigned variant, uint8_t state[88],
                                 const uint8_t *input, size_t length)
{
    if (!state || !llmopt_variant_available(
            variant, LLMOPT_VARIANT_ALGO_XXH64_STREAM)) {
        return false;
    }
    return xxh64_stream_update((LlmoptXxh64StreamingState *)state,
                               input, length);
}

typedef struct LlmoptSha256StreamingState {
    uint32_t h[8];
    uint32_t nl, nh;
    uint8_t data[64];
    uint32_t num, md_len;
} LlmoptSha256StreamingState;

_Static_assert(sizeof(LlmoptSha256StreamingState) == 112,
               "pinned SHA256_CTX streaming layout");

static bool sha256_stream_update(LlmoptSha256StreamingState *state,
                                 const uint8_t *input, size_t length)
{
    const uint8_t *current = input;
    uint32_t low;
    size_t blocks;

    if (length == 0) {
        return true;
    }
    if (!input) {
        return false;
    }
    low = state->nl + ((uint32_t)length << 3);
    if (low < state->nl) {
        state->nh++;
    }
    state->nh += length >> 29;
    state->nl = low;
    if (state->num) {
        if (length >= 64 || length + state->num >= 64) {
            size_t fill = 64 - state->num;
            memcpy(state->data + state->num, current, fill);
            sha256_portable(state->h, state->data);
            current += fill;
            length -= fill;
            state->num = 0;
            memset(state->data, 0, sizeof(state->data));
        } else {
            memcpy(state->data + state->num, current, length);
            state->num += length;
            return true;
        }
    }
    blocks = length / 64;
    while (blocks--) {
        sha256_portable(state->h, current);
        current += 64;
        length -= 64;
    }
    if (length) {
        state->num = length;
        memcpy(state->data, current, length);
    }
    return true;
}

bool llmopt_variant_sha256_stream(unsigned variant, uint8_t state[112],
                                  const uint8_t *input, size_t length)
{
    if (!state || !llmopt_variant_available(
            variant, LLMOPT_VARIANT_ALGO_SHA256_STREAM)) {
        return false;
    }
    return sha256_stream_update((LlmoptSha256StreamingState *)state,
                                input, length);
}

/* Exact host mirror of the pinned libsamplerate 2ccde956 mono call shape. */
typedef struct LlmoptSamplerateState {
    void *vt;
    double last_ratio, last_position;
    int32_t error;
    int32_t channels;
    int32_t mode;
    int32_t padding;
    void *callback_func;
    void *user_callback_data;
    int64_t saved_frames;
    const float *saved_data;
    void *private_data;
} LlmoptSamplerateState;

typedef struct LlmoptSamplerateData {
    const float *data_in;
    float *data_out;
    int64_t input_frames, output_frames;
    int64_t input_frames_used, output_frames_gen;
    int32_t end_of_input;
    int32_t padding;
    double src_ratio;
} LlmoptSamplerateData;

typedef struct LlmoptSincFilter {
    int32_t sinc_magic_marker;
    int32_t padding;
    int64_t in_count, in_used;
    int64_t out_count, out_gen;
    int32_t coeff_half_len, index_inc;
    double src_ratio, input_index;
    const float *coeffs;
    int32_t b_current, b_end, b_real_end, b_len;
    double left_calc[128], right_calc[128];
    float *buffer;
} LlmoptSincFilter;

_Static_assert(sizeof(LlmoptSamplerateState) == 80,
               "pinned SRC_STATE layout");
_Static_assert(offsetof(LlmoptSamplerateState, private_data) == 72,
               "pinned SRC_STATE private_data offset");
_Static_assert(sizeof(LlmoptSamplerateData) == 64,
               "pinned SRC_DATA layout");
_Static_assert(offsetof(LlmoptSamplerateData, src_ratio) == 56,
               "pinned SRC_DATA ratio offset");
_Static_assert(sizeof(LlmoptSincFilter) == 2144,
               "pinned SINC_FILTER layout");
_Static_assert(offsetof(LlmoptSincFilter, coeffs) == 64,
               "pinned SINC_FILTER coefficient offset");
_Static_assert(offsetof(LlmoptSincFilter, buffer) == 2136,
               "pinned SINC_FILTER buffer offset");

static inline int32_t samplerate_lrint(double value)
{
    return (int32_t)lrint(value);
}

static inline double samplerate_fmod_one(double value)
{
    double result = value - samplerate_lrint(value);
    return result < 0.0 ? result + 1.0 : result;
}

static inline int32_t samplerate_double_to_fp(double value)
{
    return samplerate_lrint(value * 4096.0);
}

static inline double samplerate_fp_fraction(int32_t value)
{
    return (value & 4095) * (1.0 / 4096.0);
}

static inline double samplerate_fma_portable(double a, double b, double c)
{
    return fma(a, b, c);
}

#if defined(__x86_64__)
__attribute__((target("fma")))
static double samplerate_fma_optimized(double a, double b, double c)
{
    return __builtin_fma(a, b, c);
}
#endif

static inline double samplerate_fma(unsigned variant,
                                    double a, double b, double c)
{
#if defined(__x86_64__)
    if (variant == LLMOPT_VARIANT_X86_64_OPTIMIZED) {
        return samplerate_fma_optimized(a, b, c);
    }
#endif
    return samplerate_fma_portable(a, b, c);
}

static double samplerate_calc_output(unsigned variant,
                                     LlmoptSincFilter *filter,
                                     int32_t increment,
                                     int32_t start_filter_index)
{
    int32_t max_filter_index = filter->coeff_half_len << 12;
    int32_t filter_index = start_filter_index;
    int32_t coeff_count = (max_filter_index - filter_index) / increment;
    int32_t data_index;
    double left = 0.0, right = 0.0;

    filter_index += coeff_count * increment;
    data_index = filter->b_current - coeff_count;
    do {
        double fraction = samplerate_fp_fraction(filter_index);
        int32_t index = filter_index >> 12;
        double base = filter->coeffs[index];
        double difference = (double)(filter->coeffs[index + 1] -
                                     filter->coeffs[index]);
        double coefficient = samplerate_fma(variant, fraction,
                                             difference, base);
        left = samplerate_fma(variant, coefficient,
                              filter->buffer[data_index], left);
        filter_index -= increment;
        data_index++;
    } while (filter_index >= 0);

    filter_index = increment - start_filter_index;
    coeff_count = (max_filter_index - filter_index) / increment;
    filter_index += coeff_count * increment;
    data_index = filter->b_current + 1 + coeff_count;
    do {
        double fraction = samplerate_fp_fraction(filter_index);
        int32_t index = filter_index >> 12;
        double base = filter->coeffs[index];
        double difference = (double)(filter->coeffs[index + 1] -
                                     filter->coeffs[index]);
        double coefficient = samplerate_fma(variant, fraction,
                                             difference, base);
        right = samplerate_fma(variant, coefficient,
                               filter->buffer[data_index], right);
        filter_index -= increment;
        data_index--;
    } while (filter_index > 0);
    return left + right;
}

static int32_t samplerate_prepare_data(LlmoptSincFilter *filter,
                                       int channels,
                                       LlmoptSamplerateData *data,
                                       int half_filter_chan_len)
{
    int len = 0;

    if (filter->b_real_end >= 0 || data->data_in == NULL) {
        return 0;
    }
    if (filter->b_current == 0) {
        len = filter->b_len - 2 * half_filter_chan_len;
        filter->b_current = filter->b_end = half_filter_chan_len;
    } else if (filter->b_end + half_filter_chan_len + channels < filter->b_len) {
        len = filter->b_len - filter->b_current - half_filter_chan_len;
        if (len < 0) {
            len = 0;
        }
    } else {
        len = filter->b_end - filter->b_current;
        memmove(filter->buffer,
                filter->buffer + filter->b_current - half_filter_chan_len,
                (half_filter_chan_len + len) * sizeof(*filter->buffer));
        filter->b_current = half_filter_chan_len;
        filter->b_end = filter->b_current + len;
        len = filter->b_len - filter->b_current - half_filter_chan_len;
        if (len < 0) {
            len = 0;
        }
    }
    if (filter->in_count - filter->in_used < len) {
        len = filter->in_count - filter->in_used;
    }
    len -= len % channels;
    if (len < 0 || filter->b_end + len > filter->b_len) {
        return 22;
    }
    memcpy(filter->buffer + filter->b_end,
           data->data_in + filter->in_used,
           len * sizeof(*filter->buffer));
    filter->b_end += len;
    filter->in_used += len;
    if (filter->in_used == filter->in_count &&
        filter->b_end - filter->b_current < 2 * half_filter_chan_len &&
        data->end_of_input) {
        if (filter->b_len - filter->b_end < half_filter_chan_len + 5) {
            len = filter->b_end - filter->b_current;
            memmove(filter->buffer,
                    filter->buffer + filter->b_current - half_filter_chan_len,
                    (half_filter_chan_len + len) * sizeof(*filter->buffer));
            filter->b_current = half_filter_chan_len;
            filter->b_end = filter->b_current + len;
        }
        filter->b_real_end = filter->b_end;
        len = half_filter_chan_len + 5;
        if (filter->b_end + len > filter->b_len) {
            len = filter->b_len - filter->b_end;
        }
        memset(filter->buffer + filter->b_end, 0,
               len * sizeof(*filter->buffer));
        filter->b_end += len;
    }
    return 0;
}

bool llmopt_variant_fp_samplerate(unsigned variant, uint8_t state_bytes[80],
                                  uint8_t data_bytes[64],
                                  uint8_t filter_bytes[2144],
                                  const float *coefficients,
                                  size_t coefficient_count,
                                  float *buffer, size_t buffer_count,
                                  const float *input, size_t input_count,
                                  float *output, size_t output_count)
{
    LlmoptSamplerateState *state = (LlmoptSamplerateState *)state_bytes;
    LlmoptSamplerateData *data = (LlmoptSamplerateData *)data_bytes;
    LlmoptSincFilter *filter = (LlmoptSincFilter *)filter_bytes;
    double input_index, src_ratio, count, float_increment, terminate, rem;
    int32_t increment, start_filter_index;
    int half_filter_chan_len, samples_in_hand;

    if (!state || !data || !filter || !coefficients || !buffer || !output ||
        !llmopt_variant_available(variant, LLMOPT_VARIANT_ALGO_FP_SAMPLERATE) ||
        state->channels != 1 || filter->coeff_half_len < 1 ||
        filter->index_inc <= 0 || coefficient_count < (size_t)filter->coeff_half_len + 2 ||
        buffer_count != (size_t)filter->b_len ||
        input_count < (size_t)data->input_frames ||
        output_count < (size_t)data->output_frames) {
        return false;
    }
    state->private_data = filter;
    data->data_in = input;
    data->data_out = output;
    filter->coeffs = coefficients;
    filter->buffer = buffer;
    filter->in_count = data->input_frames;
    filter->out_count = data->output_frames;
    filter->in_used = filter->out_gen = 0;
    src_ratio = state->last_ratio;
    if (src_ratio < 1.0 / 256.0 || src_ratio > 256.0) {
        return false;
    }
    count = (filter->coeff_half_len + 2.0) / filter->index_inc;
    if ((state->last_ratio < data->src_ratio ? state->last_ratio : data->src_ratio) < 1.0) {
        count /= state->last_ratio < data->src_ratio ? state->last_ratio : data->src_ratio;
    }
    half_filter_chan_len = samplerate_lrint(count) + 1;
    input_index = state->last_position;
    rem = samplerate_fmod_one(input_index);
    filter->b_current = (filter->b_current +
        samplerate_lrint(input_index - rem)) % filter->b_len;
    input_index = rem;
    terminate = 1.0 / src_ratio + 1e-20;
    while (filter->out_gen < filter->out_count) {
        samples_in_hand = (filter->b_end - filter->b_current + filter->b_len) % filter->b_len;
        if (samples_in_hand <= half_filter_chan_len) {
            state->error = samplerate_prepare_data(filter, 1, data,
                                                    half_filter_chan_len);
            if (state->error != 0) {
                return false;
            }
            samples_in_hand = (filter->b_end - filter->b_current + filter->b_len) % filter->b_len;
            if (samples_in_hand <= half_filter_chan_len) {
                break;
            }
        }
        if (filter->b_real_end >= 0 &&
            filter->b_current + input_index + terminate > filter->b_real_end) {
            break;
        }
        if (filter->out_count > 0 &&
            fabs(state->last_ratio - data->src_ratio) > 1e-10) {
            volatile double product = filter->out_gen *
                (data->src_ratio - state->last_ratio);
            volatile double quotient = product / filter->out_count;
            src_ratio = state->last_ratio + quotient;
        }
        float_increment = filter->index_inc *
            (src_ratio < 1.0 ? src_ratio : 1.0);
        increment = samplerate_double_to_fp(float_increment);
        start_filter_index = samplerate_double_to_fp(input_index * float_increment);
        output[filter->out_gen] = (float)((float_increment / filter->index_inc) *
            samplerate_calc_output(variant, filter, increment,
                                   start_filter_index));
        filter->out_gen++;
        input_index += 1.0 / src_ratio;
        rem = samplerate_fmod_one(input_index);
        filter->b_current = (filter->b_current +
            samplerate_lrint(input_index - rem)) % filter->b_len;
        input_index = rem;
    }
    state->last_position = input_index;
    state->last_ratio = src_ratio;
    data->input_frames_used = filter->in_used;
    data->output_frames_gen = filter->out_gen;
    return true;
}

#ifndef LINUX_USER_LLMOPT_VARIANTS_H
#define LINUX_USER_LLMOPT_VARIANTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum LlmoptHostVariant {
    LLMOPT_VARIANT_PORTABLE_C = 0,
    LLMOPT_VARIANT_X86_64_OPTIMIZED = 1,
} LlmoptHostVariant;

typedef enum LlmoptVariantAlgorithm {
    LLMOPT_VARIANT_ALGO_XXH64,
    LLMOPT_VARIANT_ALGO_SHA256,
    LLMOPT_VARIANT_ALGO_MD5,
    LLMOPT_VARIANT_ALGO_CRC32,
    LLMOPT_VARIANT_ALGO_ADLER32,
    LLMOPT_VARIANT_ALGO_MEMCPY,
    LLMOPT_VARIANT_ALGO_LZ_MATCH_COPY,
    LLMOPT_VARIANT_ALGO_MEMSET,
    LLMOPT_VARIANT_ALGO_XXH64_STREAM,
    LLMOPT_VARIANT_ALGO_SHA256_STREAM,
} LlmoptVariantAlgorithm;

bool llmopt_variant_available(LlmoptHostVariant variant,
                              LlmoptVariantAlgorithm algorithm);
bool llmopt_variant_md5(unsigned variant, uint32_t state[4],
                        const uint8_t *input, size_t blocks);
bool llmopt_variant_sha256(unsigned variant, uint32_t state[8],
                           const uint8_t *input, size_t blocks);
bool llmopt_variant_xxh64(unsigned variant, const uint8_t *input,
                          size_t length, uint64_t seed, uint64_t *result);
bool llmopt_variant_crc32(unsigned variant, const uint8_t *input,
                          size_t length, uint32_t initial, uint32_t *result);
bool llmopt_variant_adler32(unsigned variant, const uint8_t *input,
                            size_t length, uint32_t initial, uint32_t *result);
bool llmopt_variant_memcpy(unsigned variant, uint8_t *destination,
                           const uint8_t *source, size_t length);
bool llmopt_variant_lz_match_copy(unsigned variant, uint8_t *output,
                                  size_t length, size_t distance);
bool llmopt_variant_memset(unsigned variant, uint8_t *output,
                           uint8_t value, size_t length);
bool llmopt_variant_xxh64_stream(unsigned variant, uint8_t state[88],
                                 const uint8_t *input, size_t length);
bool llmopt_variant_sha256_stream(unsigned variant, uint8_t state[112],
                                  const uint8_t *input, size_t length);

#endif

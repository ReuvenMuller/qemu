#ifndef LINUX_USER_LLMOPT_VARIANTS_H
#define LINUX_USER_LLMOPT_VARIANTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum LlmoptHostVariant {
    LLMOPT_VARIANT_PORTABLE_C = 0,
    LLMOPT_VARIANT_X86_64_OPTIMIZED = 1,
} LlmoptHostVariant;

bool llmopt_variant_available(LlmoptHostVariant variant, bool sha256);
bool llmopt_variant_md5(unsigned variant, uint32_t state[4],
                        const uint8_t *input, size_t blocks);
bool llmopt_variant_sha256(unsigned variant, uint32_t state[8],
                           const uint8_t *input, size_t blocks);

#endif

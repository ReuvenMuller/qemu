#ifndef LLMOPT_XXH64_BULK_IMPL_H
#define LLMOPT_XXH64_BULK_IMPL_H

typedef struct LlmoptXxh64BulkState {
    uint64_t total_len;
    uint64_t v[4];
    uint8_t buffer[32];
    uint32_t memsize;
    uint32_t reserved32;
    uint64_t reserved64;
} LlmoptXxh64BulkState;

_Static_assert(sizeof(LlmoptXxh64BulkState) == 88,
               "pinned XXH64 bulk state layout");

static inline __attribute__((always_inline))
uint64_t llmopt_xxh64_bulk_rotl64(uint64_t value, unsigned count)
{
    return (value << count) | (value >> (64 - count));
}

static inline __attribute__((always_inline))
uint64_t llmopt_xxh64_bulk_load_le64(const uint8_t *input)
{
    return (uint64_t)input[0] | (uint64_t)input[1] << 8 |
           (uint64_t)input[2] << 16 | (uint64_t)input[3] << 24 |
           (uint64_t)input[4] << 32 | (uint64_t)input[5] << 40 |
           (uint64_t)input[6] << 48 | (uint64_t)input[7] << 56;
}

static inline __attribute__((always_inline))
uint64_t llmopt_xxh64_bulk_round(uint64_t accumulator, uint64_t lane)
{
    const uint64_t prime1 = UINT64_C(11400714785074694791);
    const uint64_t prime2 = STREAM_MUTANT == 3
                          ? UINT64_C(14029467366897019729)
                          : UINT64_C(14029467366897019727);

    return llmopt_xxh64_bulk_rotl64(accumulator + lane * prime2, 31) * prime1;
}

static inline __attribute__((always_inline))
void llmopt_xxh64_bulk_buffered_stripe(LlmoptXxh64BulkState *state,
                                       const uint8_t *input)
{
    state->v[0] = llmopt_xxh64_bulk_round(
        state->v[0], llmopt_xxh64_bulk_load_le64(input));
    state->v[1] = llmopt_xxh64_bulk_round(
        state->v[1], llmopt_xxh64_bulk_load_le64(input + 8));
    state->v[2] = llmopt_xxh64_bulk_round(
        state->v[2], llmopt_xxh64_bulk_load_le64(input + 16));
    state->v[3] = llmopt_xxh64_bulk_round(
        state->v[3], llmopt_xxh64_bulk_load_le64(input + 24));
    if (STREAM_MUTANT == 5) {
        uint64_t temporary = state->v[0];

        state->v[0] = state->v[3];
        state->v[3] = temporary;
    }
}

static inline __attribute__((always_inline))
bool llmopt_xxh64_stream_update_bulk_impl(LlmoptXxh64BulkState *state,
                                          const uint8_t *input,
                                          size_t length)
{
    const uint8_t *current = input;
    const uint8_t *end;

    if (input == NULL) {
        return length == 0;
    }
    end = input + length;
    if (STREAM_MUTANT != 1) {
        state->total_len += length;
    }
    if ((STREAM_MUTANT == 2 ? state->memsize + length <= 32
                            : state->memsize + length < 32)) {
        memcpy(state->buffer + state->memsize, input, length);
        state->memsize += (uint32_t)length;
        return true;
    }
    if (state->memsize != 0) {
        size_t fill = 32 - state->memsize;

        memcpy(state->buffer + state->memsize, current, fill);
        llmopt_xxh64_bulk_buffered_stripe(state, state->buffer);
        current += fill;
        if (STREAM_MUTANT != 4) {
            state->memsize = 0;
        }
    }
    if (current + 32 <= end) {
        const uint8_t *limit = end - 32;
        uint64_t v0 = state->v[0];
        uint64_t v1 = state->v[1];
        uint64_t v2 = state->v[2];
        uint64_t v3 = state->v[3];

        do {
            v0 = llmopt_xxh64_bulk_round(
                v0, llmopt_xxh64_bulk_load_le64(current));
            v1 = llmopt_xxh64_bulk_round(
                v1, llmopt_xxh64_bulk_load_le64(current + 8));
            v2 = llmopt_xxh64_bulk_round(
                v2, llmopt_xxh64_bulk_load_le64(current + 16));
            v3 = llmopt_xxh64_bulk_round(
                v3, llmopt_xxh64_bulk_load_le64(current + 24));
            if (STREAM_MUTANT == 5) {
                uint64_t temporary = v0;

                v0 = v3;
                v3 = temporary;
            }
            current += 32;
        } while (current <= limit);
        state->v[0] = v0;
        state->v[1] = v1;
        state->v[2] = v2;
        state->v[3] = v3;
    }
    if (current < end) {
        size_t tail = (size_t)(end - current);

        if (STREAM_MUTANT != 6) {
            memcpy(state->buffer, current, tail);
        }
        state->memsize = (uint32_t)tail;
    }
    return true;
}

#endif

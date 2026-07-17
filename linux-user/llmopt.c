/*
 * Cache-backed, fail-closed linux-user dispatch-entry substitutions.
 *
 * The offline installer validates verdict-cache and catalog authority and
 * emits a strict per-process map.  This file loads that map exactly once
 * before guest execution.  Every matching entry rechecks exact code bytes,
 * dynamic state, operands, and mapped memory before any replacement runs.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "exec/llmopt.h"
#include "qemu.h"
#include "user-internals.h"

#define LLMOPT_MAX_ENTRIES 64
#define LLMOPT_MAX_MAP_BYTES (1024 * 1024)
#define LLMOPT_VALIDATION_QEMU_SHA256 \
    "623e64d16e1d01816ecc434070bf3a5486ee40273bc28d2d0b6a14c2bd77b931"

#ifndef TARGET_AARCH64

void llmopt_initialize(bool debugger_active, const char *guest_binary)
{
    if (g_strcmp0(getenv("QEMU_LLMOPT"), "1") == 0) {
        fprintf(stderr, "LLMOPT disabled: target adapter is not AArch64\n");
    }
}

void llmopt_report(void)
{
}

LlmoptDispatchResult llmopt_try_dispatch(CPUState *cpu, vaddr pc)
{
    return LLMOPT_NOT_APPLICABLE;
}

#else

typedef enum LlmoptAlgorithm {
    LLMOPT_ALGO_XXH64,
    LLMOPT_ALGO_SHA256_BLOCK,
    LLMOPT_ALGO_MD5_BLOCK,
    LLMOPT_ALGO_CRC32,
    LLMOPT_ALGO_ADLER32,
} LlmoptAlgorithm;

typedef struct LlmoptEntry {
    LlmoptAlgorithm algorithm;
    char catalog_id[32];
    char verdict_id[37];
    uint64_t pc;
    size_t code_size;
    uint8_t code_sha256[32];
    size_t max_input;
    size_t state_bytes;
} LlmoptEntry;

typedef struct LlmoptRuntime {
    bool initialized;
    bool enabled;
    bool trace;
    bool report_enabled;
    bool reported;
    bool debugger_active;
    bool baseline_only;
    bool force_guard_fail_once;
    bool forced_guard_fired;
    bool baseline_region_active;
    bool pending_recheck;
    uint64_t baseline_return_pc;
    uint64_t baseline_start_ns;
    uint64_t fallback_pc;
    size_t entry_count;
    LlmoptEntry entries[LLMOPT_MAX_ENTRIES];
    uint64_t attempts;
    uint64_t guard_checks;
    uint64_t hits;
    uint64_t guarded_fallbacks;
    uint64_t rechecks_after_fallback;
    uint64_t code_rejects;
    uint64_t state_rejects;
    uint64_t memory_rejects;
    uint64_t forced_rejects;
    uint64_t unguarded_executions;
    uint64_t baseline_region_count;
    uint64_t baseline_region_ns;
    uint64_t substitution_region_count;
    uint64_t substitution_region_ns;
} LlmoptRuntime;

static LlmoptRuntime runtime;

static bool parse_u64(const char *text, int base, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text) {
        return false;
    }
    errno = 0;
    parsed = g_ascii_strtoull(text, &end, base);
    if (errno || !end || *end) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool parse_sha256(const char *text, uint8_t output[32])
{
    if (!text || strlen(text) != 64) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        int hi = g_ascii_xdigit_value(text[i * 2]);
        int lo = g_ascii_xdigit_value(text[i * 2 + 1]);
        if (hi < 0 || lo < 0 || g_ascii_isupper(text[i * 2]) ||
            g_ascii_isupper(text[i * 2 + 1])) {
            return false;
        }
        output[i] = (hi << 4) | lo;
    }
    return true;
}

static bool guest_binary_matches(const char *path, const char *expected)
{
    g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t buffer[65536];
    FILE *stream;
    size_t length;
    bool matched = false;

    if (!checksum || !path || !(stream = fopen(path, "rb"))) {
        return false;
    }
    while ((length = fread(buffer, 1, sizeof(buffer), stream)) > 0) {
        g_checksum_update(checksum, buffer, length);
    }
    if (!ferror(stream)) {
        matched = strcmp(g_checksum_get_string(checksum), expected) == 0;
    }
    fclose(stream);
    return matched;
}

static bool algorithm_for_catalog(const char *catalog, LlmoptAlgorithm *algo,
                                  size_t *expected_state)
{
    if (strcmp(catalog, "digest.xxh64") == 0) {
        *algo = LLMOPT_ALGO_XXH64;
        *expected_state = 0;
    } else if (strcmp(catalog, "digest.sha256.block") == 0) {
        *algo = LLMOPT_ALGO_SHA256_BLOCK;
        *expected_state = 32;
    } else if (strcmp(catalog, "digest.md5.block") == 0) {
        *algo = LLMOPT_ALGO_MD5_BLOCK;
        *expected_state = 16;
    } else if (strcmp(catalog, "checksum.crc32.ieee") == 0) {
        *algo = LLMOPT_ALGO_CRC32;
        *expected_state = 0;
    } else if (strcmp(catalog, "checksum.adler32") == 0) {
        *algo = LLMOPT_ALGO_ADLER32;
        *expected_state = 0;
    } else {
        return false;
    }
    return true;
}

static bool parse_entry_line(const char *line, LlmoptEntry *entry)
{
    g_auto(GStrv) fields = g_strsplit(line, "\t", -1);
    uint64_t pc, code_size, max_input, state_bytes;
    size_t expected_state;

    if (g_strv_length(fields) != 8 ||
        !algorithm_for_catalog(fields[0], &entry->algorithm, &expected_state) ||
        strlen(fields[0]) >= sizeof(entry->catalog_id) ||
        strlen(fields[1]) != 36 || strlen(fields[5]) == 0 ||
        strcmp(fields[5], "portable_c") != 0 ||
        !parse_u64(fields[2], 16, &pc) || !pc ||
        !parse_u64(fields[3], 10, &code_size) || !code_size ||
        code_size > LLMOPT_MAX_MAP_BYTES ||
        !parse_sha256(fields[4], entry->code_sha256) ||
        !parse_u64(fields[6], 10, &max_input) || max_input > 67108864 ||
        !parse_u64(fields[7], 10, &state_bytes) ||
        state_bytes != expected_state || code_size > SIZE_MAX ||
        max_input > SIZE_MAX) {
        return false;
    }
    g_strlcpy(entry->catalog_id, fields[0], sizeof(entry->catalog_id));
    g_strlcpy(entry->verdict_id, fields[1], sizeof(entry->verdict_id));
    entry->pc = pc;
    entry->code_size = code_size;
    entry->max_input = max_input;
    entry->state_bytes = state_bytes;
    return true;
}

void llmopt_report(void)
{
    if (!runtime.enabled || !runtime.report_enabled || runtime.reported) {
        return;
    }
    runtime.reported = true;
    fprintf(stderr,
            "LLMOPT_REPORT entries=%zu attempts=%" PRIu64
            " guard_checks=%" PRIu64 " hits=%" PRIu64
            " guarded_fallbacks=%" PRIu64 " rechecks_after_fallback=%" PRIu64
            " code_rejects=%" PRIu64 " state_rejects=%" PRIu64
            " memory_rejects=%" PRIu64 " forced_rejects=%" PRIu64
            " unguarded_executions=%" PRIu64
            " baseline_region_count=%" PRIu64
            " baseline_region_ns=%" PRIu64
            " substitution_region_count=%" PRIu64
            " substitution_region_ns=%" PRIu64 "\n",
            runtime.entry_count, runtime.attempts, runtime.guard_checks,
            runtime.hits, runtime.guarded_fallbacks,
            runtime.rechecks_after_fallback, runtime.code_rejects,
            runtime.state_rejects, runtime.memory_rejects,
            runtime.forced_rejects, runtime.unguarded_executions,
            runtime.baseline_region_count, runtime.baseline_region_ns,
            runtime.substitution_region_count, runtime.substitution_region_ns);
}

static void disable_map(const char *reason)
{
    runtime.enabled = false;
    runtime.entry_count = 0;
    fprintf(stderr, "LLMOPT disabled: %s\n", reason);
}

void llmopt_initialize(bool debugger_active, const char *guest_binary)
{
    const char *path = getenv("QEMU_LLMOPT_MAP");
    g_autofree char *contents = NULL;
    g_auto(GStrv) lines = NULL;
    gsize length = 0;
    uint64_t declared_count;
    uint8_t guest_sha256[32];
    LlmoptEntry parsed[LLMOPT_MAX_ENTRIES] = { 0 };

    if (runtime.initialized) {
        return;
    }
    runtime.initialized = true;
    runtime.debugger_active = debugger_active;
    runtime.trace = g_strcmp0(getenv("QEMU_LLMOPT_TRACE"), "1") == 0;
    runtime.report_enabled = runtime.trace ||
        g_strcmp0(getenv("QEMU_LLMOPT_REPORT"), "1") == 0;
    runtime.baseline_only =
        g_strcmp0(getenv("QEMU_LLMOPT_BASELINE_ONLY"), "1") == 0;
    runtime.force_guard_fail_once =
        g_strcmp0(getenv("QEMU_LLMOPT_FORCE_GUARD_FAIL_ONCE"), "1") == 0;
    if (g_strcmp0(getenv("QEMU_LLMOPT"), "1") != 0) {
        return;
    }
    if (!path || !*path ||
        !g_file_get_contents(path, &contents, &length, NULL) ||
        length == 0 || length > LLMOPT_MAX_MAP_BYTES ||
        contents[length - 1] != '\n') {
        disable_map("missing, unreadable, oversized, or unterminated map");
        return;
    }
    lines = g_strsplit(contents, "\n", -1);
    if (strcmp(lines[0], "llmopt_dispatch_map.v1") != 0 ||
        !g_str_has_prefix(lines[1], "guest_sha256\t") ||
        !parse_sha256(lines[1] + strlen("guest_sha256\t"), guest_sha256) ||
        !guest_binary_matches(guest_binary,
                              lines[1] + strlen("guest_sha256\t")) ||
        !g_str_has_prefix(lines[2], "qemu_validation_sha256\t") ||
        strcmp(lines[2] + strlen("qemu_validation_sha256\t"),
               LLMOPT_VALIDATION_QEMU_SHA256) != 0 ||
        !g_str_has_prefix(lines[3], "entry_count\t") ||
        !parse_u64(lines[3] + strlen("entry_count\t"), 10, &declared_count) ||
        declared_count == 0 || declared_count > LLMOPT_MAX_ENTRIES ||
        g_strv_length(lines) != declared_count + 5 ||
        lines[declared_count + 4][0] != '\0') {
        disable_map("map header or validation-QEMU identity rejected");
        return;
    }
    for (size_t i = 0; i < declared_count; i++) {
        if (!parse_entry_line(lines[i + 4], &parsed[i])) {
            disable_map("unsupported or malformed entry row");
            return;
        }
        for (size_t j = 0; j < i; j++) {
            if (parsed[i].pc == parsed[j].pc) {
                disable_map("ambiguous duplicate entry PC");
                return;
            }
        }
    }
    memcpy(runtime.entries, parsed, declared_count * sizeof(parsed[0]));
    runtime.entry_count = declared_count;
    runtime.enabled = true;
    atexit(llmopt_report);
    if (runtime.trace) {
        fprintf(stderr, "LLMOPT_MAP_READY entries=%zu immutable=1\n",
                runtime.entry_count);
    }
}

static inline uint64_t rotl64(uint64_t value, unsigned count)
{
    return (value << count) | (value >> (64 - count));
}

static inline uint32_t rotl32(uint32_t value, unsigned count)
{
    return (value << count) | (value >> (32 - count));
}

static inline uint32_t rotr32(uint32_t value, unsigned count)
{
    return (value >> count) | (value << (32 - count));
}

static uint64_t now_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + value.tv_nsec;
}

#define XXH_P1 UINT64_C(11400714785074694791)
#define XXH_P2 UINT64_C(14029467366897019727)
#define XXH_P3 UINT64_C(1609587929392839161)
#define XXH_P4 UINT64_C(9650029242287828579)
#define XXH_P5 UINT64_C(2870177450012600261)

static uint64_t xxh_round(uint64_t acc, uint64_t input)
{
    acc += input * XXH_P2;
    return rotl64(acc, 31) * XXH_P1;
}

static uint64_t host_xxh64(const uint8_t *p, size_t len, uint64_t seed)
{
    const uint8_t *end = p + len;
    uint64_t hash;

    if (len >= 32) {
        const uint8_t *limit = end - 32;
        uint64_t v1 = seed + XXH_P1 + XXH_P2;
        uint64_t v2 = seed + XXH_P2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_P1;
        do {
            v1 = xxh_round(v1, ldq_le_p(p)); p += 8;
            v2 = xxh_round(v2, ldq_le_p(p)); p += 8;
            v3 = xxh_round(v3, ldq_le_p(p)); p += 8;
            v4 = xxh_round(v4, ldq_le_p(p)); p += 8;
        } while (p <= limit);
        hash = rotl64(v1, 1) + rotl64(v2, 7) +
               rotl64(v3, 12) + rotl64(v4, 18);
        v1 = xxh_round(0, v1); hash = (hash ^ v1) * XXH_P1 + XXH_P4;
        v2 = xxh_round(0, v2); hash = (hash ^ v2) * XXH_P1 + XXH_P4;
        v3 = xxh_round(0, v3); hash = (hash ^ v3) * XXH_P1 + XXH_P4;
        v4 = xxh_round(0, v4); hash = (hash ^ v4) * XXH_P1 + XXH_P4;
    } else {
        hash = seed + XXH_P5;
    }
    hash += len;
    while (p + 8 <= end) {
        uint64_t lane = xxh_round(0, ldq_le_p(p));
        hash = rotl64(hash ^ lane, 27) * XXH_P1 + XXH_P4;
        p += 8;
    }
    if (p + 4 <= end) {
        hash = rotl64(hash ^ (uint64_t)(uint32_t)ldl_le_p(p) * XXH_P1, 23) *
               XXH_P2 + XXH_P3;
        p += 4;
    }
    while (p < end) {
        hash = rotl64(hash ^ (uint64_t)*p++ * XXH_P5, 11) * XXH_P1;
    }
    hash ^= hash >> 33;
    hash *= XXH_P2;
    hash ^= hash >> 29;
    hash *= XXH_P3;
    hash ^= hash >> 32;
    return hash;
}

static uint32_t host_adler32(const uint8_t *data, size_t len, uint32_t initial)
{
    uint32_t s1 = initial & 0xffff;
    uint32_t s2 = initial >> 16;
    for (size_t i = 0; i < len; i++) {
        s1 = (s1 + data[i]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) | s1;
}

static uint32_t host_crc32(const uint8_t *data, size_t len, uint32_t initial)
{
    uint32_t crc = initial ^ UINT32_MAX;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & -(crc & 1));
        }
    }
    return crc ^ UINT32_MAX;
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

static void host_md5_block(uint32_t state[4], const uint8_t block[64])
{
    uint32_t words[16];
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    for (size_t i = 0; i < 16; i++) {
        words[i] = ldl_le_p(block + i * 4);
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
        saved_d = d;
        d = c;
        c = b;
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

static void host_sha256_block(uint32_t state[8], const uint8_t block[64])
{
    uint32_t words[64];
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (size_t i = 0; i < 16; i++) {
        words[i] = ldl_be_p(block + i * 4);
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

static bool single_guest_cpu(void)
{
    CPUState *candidate;
    unsigned count = 0;

    cpu_list_lock();
    CPU_FOREACH(candidate) {
        if (++count > 1) {
            break;
        }
    }
    cpu_list_unlock();
    return count == 1;
}

static void sha256_buffer(const uint8_t *data, size_t length, uint8_t digest[32])
{
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    uint8_t tail[128] = { 0 };
    size_t complete = length & ~(size_t)63;
    size_t remaining = length - complete;
    size_t tail_length = remaining < 56 ? 64 : 128;

    for (size_t offset = 0; offset < complete; offset += 64) {
        host_sha256_block(state, data + offset);
    }
    memcpy(tail, data + complete, remaining);
    tail[remaining] = 0x80;
    stq_be_p(tail + tail_length - 8, (uint64_t)length * 8);
    host_sha256_block(state, tail);
    if (tail_length == 128) {
        host_sha256_block(state, tail + 64);
    }
    for (size_t i = 0; i < 8; i++) {
        stl_be_p(digest + i * 4, state[i]);
    }
}

static bool entry_bytes_match(const LlmoptEntry *entry)
{
    g_autofree uint8_t *code = g_try_malloc(entry->code_size);
    uint8_t digest[32];

    if (!code || copy_from_user(code, entry->pc, entry->code_size) != 0) {
        return false;
    }
    sha256_buffer(code, entry->code_size, digest);
    return memcmp(digest, entry->code_sha256, sizeof(digest)) == 0;
}

static bool ranges_overlap(uint64_t left, size_t left_len,
                           uint64_t right, size_t right_len)
{
    uint64_t left_end = left + left_len;
    uint64_t right_end = right + right_len;
    return left_end < left || right_end < right ||
           (left < right_end && right < left_end);
}

static uint8_t *copy_input(uint64_t address, uint64_t length, size_t max_input)
{
    uint8_t *copy;
    if (length > max_input || length > SIZE_MAX || address + length < address) {
        return NULL;
    }
    copy = g_try_malloc(length ? length : 1);
    if (!copy || (length && copy_from_user(copy, address, length) != 0)) {
        g_free(copy);
        return NULL;
    }
    return copy;
}

static bool substitute_scalar(CPUARMState *env, const LlmoptEntry *entry)
{
    uint64_t address = env->xregs[0];
    uint64_t length = env->xregs[1];
    uint64_t initial = env->xregs[2];
    g_autofree uint8_t *input = copy_input(address, length, entry->max_input);
    uint64_t result;

    if (!input) {
        return false;
    }
    switch (entry->algorithm) {
    case LLMOPT_ALGO_XXH64:
        result = host_xxh64(input, length, initial);
        break;
    case LLMOPT_ALGO_CRC32:
        result = host_crc32(input, length, initial);
        break;
    case LLMOPT_ALGO_ADLER32:
        result = host_adler32(input, length, initial);
        break;
    default:
        return false;
    }
    env->xregs[0] = result;
    env->pc = env->xregs[30];
    return true;
}

static bool substitute_block(CPUARMState *env, const LlmoptEntry *entry)
{
    uint64_t state_address = env->xregs[0];
    uint64_t input_address = env->xregs[1];
    uint8_t input[64];
    uint8_t *state_host;
    uint32_t state[8] = { 0 };

    if ((state_address & 3) || state_address + entry->state_bytes < state_address ||
        input_address + sizeof(input) < input_address ||
        ranges_overlap(state_address, entry->state_bytes,
                       input_address, sizeof(input))) {
        return false;
    }
    state_host = lock_user(VERIFY_WRITE, state_address, entry->state_bytes, 1);
    if (!state_host || copy_from_user(input, input_address, sizeof(input)) != 0) {
        if (state_host) {
            unlock_user(state_host, state_address, 0);
        }
        return false;
    }
    for (size_t i = 0; i < entry->state_bytes / 4; i++) {
        state[i] = ldl_le_p(state_host + i * 4);
    }
    if (entry->algorithm == LLMOPT_ALGO_MD5_BLOCK) {
        host_md5_block(state, input);
    } else if (entry->algorithm == LLMOPT_ALGO_SHA256_BLOCK) {
        host_sha256_block(state, input);
    } else {
        unlock_user(state_host, state_address, 0);
        return false;
    }
    for (size_t i = 0; i < entry->state_bytes / 4; i++) {
        stl_le_p(state_host + i * 4, state[i]);
    }
    unlock_user(state_host, state_address, entry->state_bytes);
    env->pc = env->xregs[30];
    return true;
}

static LlmoptDispatchResult guarded_fallback(vaddr pc, const char *reason)
{
    runtime.guarded_fallbacks++;
    runtime.pending_recheck = true;
    runtime.fallback_pc = pc;
    if (runtime.trace) {
        fprintf(stderr,
                "LLMOPT_GUARDED_FALLBACK pc=0x%" PRIx64
                " reason=%s guarded_fallbacks=%" PRIu64 "\n",
                (uint64_t)pc, reason, runtime.guarded_fallbacks);
    }
    return LLMOPT_GUARDED_FALLBACK;
}

LlmoptDispatchResult llmopt_try_dispatch(CPUState *cpu, vaddr pc)
{
    const LlmoptEntry *entry = NULL;
    CPUARMState *env;
    TaskState *task;
    bool guards_passed = false;
    bool substituted;
    uint64_t entry_start;

    if (!runtime.initialized || !runtime.enabled) {
        return LLMOPT_NOT_APPLICABLE;
    }
    if (runtime.baseline_region_active && pc == runtime.baseline_return_pc) {
        runtime.baseline_region_ns += now_ns() - runtime.baseline_start_ns;
        runtime.baseline_region_count++;
        runtime.baseline_region_active = false;
    }
    for (size_t i = 0; i < runtime.entry_count; i++) {
        if (runtime.entries[i].pc == pc) {
            entry = &runtime.entries[i];
            break;
        }
    }
    if (!entry) {
        return LLMOPT_NOT_APPLICABLE;
    }
    runtime.attempts++;
    runtime.guard_checks++;
    entry_start = now_ns();
    if (runtime.pending_recheck && runtime.fallback_pc == pc) {
        runtime.rechecks_after_fallback++;
        runtime.pending_recheck = false;
        if (runtime.trace) {
            fprintf(stderr, "LLMOPT_RECHECK pc=0x%" PRIx64 " count=%" PRIu64 "\n",
                    (uint64_t)pc, runtime.rechecks_after_fallback);
        }
    }
    env = cpu_env(cpu);
    task = get_task_state(cpu);
    if (!entry_bytes_match(entry)) {
        runtime.code_rejects++;
        return guarded_fallback(pc, "exact_entry_bytes");
    }
    if (runtime.debugger_active || cpu->singlestep_enabled ||
        !QTAILQ_EMPTY(&cpu->watchpoints) ||
        qatomic_read(&task->signal_pending) ||
        qatomic_read(&cpu->exit_request) || !single_guest_cpu()) {
        runtime.state_rejects++;
        return guarded_fallback(pc, "runtime_state");
    }
    if (runtime.force_guard_fail_once && !runtime.forced_guard_fired) {
        runtime.forced_guard_fired = true;
        runtime.forced_rejects++;
        return guarded_fallback(pc, "forced_test_guard");
    }
    if (runtime.baseline_only) {
        runtime.baseline_region_active = true;
        runtime.baseline_return_pc = env->xregs[30];
        runtime.baseline_start_ns = entry_start;
        return guarded_fallback(pc, "baseline_measurement");
    }
    guards_passed = true;
    if (entry->algorithm == LLMOPT_ALGO_MD5_BLOCK ||
        entry->algorithm == LLMOPT_ALGO_SHA256_BLOCK) {
        substituted = substitute_block(env, entry);
    } else {
        substituted = substitute_scalar(env, entry);
    }
    if (!substituted) {
        runtime.memory_rejects++;
        return guarded_fallback(pc, "operand_or_memory");
    }
    runtime.substitution_region_ns += now_ns() - entry_start;
    runtime.substitution_region_count++;
    if (!guards_passed) {
        runtime.unguarded_executions++;
        return guarded_fallback(pc, "internal_guard_audit");
    }
    runtime.hits++;
    if (runtime.trace) {
        fprintf(stderr,
                "LLMOPT_HIT pc=0x%" PRIx64 " catalog=%s verdict=%s"
                " guard_checked=1 hit=%" PRIu64 "\n",
                (uint64_t)pc, entry->catalog_id, entry->verdict_id,
                runtime.hits);
    }
    return LLMOPT_SUBSTITUTED;
}

#endif /* TARGET_AARCH64 */

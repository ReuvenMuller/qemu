/*
 * Cache-backed, fail-closed linux-user dispatch-entry substitutions.
 *
 * The offline installer validates verdict-cache and catalog authority and
 * emits a strict per-process map.  This file loads that map exactly once
 * before guest execution.  Exact code bytes are checked once per protected
 * code-page version epoch; dynamic state, operands, and mapped memory remain
 * per-call checks before any replacement runs.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "exec/llmopt.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/page-protection.h"
#include "llmopt-variants.h"

#define LLMOPT_MAX_ENTRIES 64
#define LLMOPT_MAX_MAP_BYTES (1024 * 1024)
#define LLMOPT_MAX_CODE_PAGES 257
#define LLMOPT_VALIDATION_QEMU_SHA256 \
    "623e64d16e1d01816ecc434070bf3a5486ee40273bc28d2d0b6a14c2bd77b931"

#ifndef TARGET_AARCH64

void llmopt_initialize(bool debugger_active, const char *guest_binary,
                       uint64_t guest_load_bias)
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
    LlmoptHostVariant variant;
    char catalog_id[32];
    char verdict_id[37];
    uint64_t pc;
    uint64_t runtime_pc;
    size_t code_size;
    uint8_t code_sha256[32];
    uint8_t implementation_sha256[32];
    uint8_t generated_code_sha256[32];
    uint8_t variant_admission_sha256[32];
    size_t max_input;
    size_t state_bytes;
    bool stable_direct;
    bool blocks_x2;
    bool pie_relative;
    bool code_verified;
    size_t page_token_count;
    LlmoptPageVersionToken page_tokens[LLMOPT_MAX_CODE_PAGES];
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
    bool force_code_change_once;
    bool forced_code_change_fired;
    bool forced_code_restore_pending;
    bool baseline_region_active;
    bool pending_recheck;
    uint64_t baseline_return_pc;
    uint64_t baseline_start_ns;
    uint64_t fallback_pc;
    uint64_t forced_code_address;
    uint8_t forced_code_original;
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
    uint64_t stable_direct_hits;
    uint64_t portable_variant_hits;
    uint64_t optimized_variant_hits;
    uint64_t code_verifications;
    uint64_t code_verification_failures;
    uint64_t page_version_checks;
    uint64_t page_version_mismatches;
    uint64_t page_change_fallbacks;
    uint64_t late_page_version_rejects;
    uint64_t forced_code_changes;
    uint64_t forced_code_restores;
    uint64_t page_write_detection_failures;
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

    size_t field_count = g_strv_length(fields);

    if (field_count != 14 ||
        !algorithm_for_catalog(fields[0], &entry->algorithm, &expected_state) ||
        strlen(fields[0]) >= sizeof(entry->catalog_id) ||
        strlen(fields[1]) != 36 || strlen(fields[5]) == 0 ||
        (strcmp(fields[5], "portable_c") != 0 &&
         strcmp(fields[5], "x86_64_optimized") != 0) ||
        !parse_u64(fields[2], 16, &pc) || !pc ||
        !parse_u64(fields[3], 10, &code_size) || !code_size ||
        code_size > LLMOPT_MAX_MAP_BYTES ||
        !parse_sha256(fields[4], entry->code_sha256) ||
        !parse_sha256(fields[10], entry->implementation_sha256) ||
        !parse_sha256(fields[11], entry->generated_code_sha256) ||
        !parse_sha256(fields[12], entry->variant_admission_sha256) ||
        !parse_u64(fields[6], 10, &max_input) || max_input > 67108864 ||
        !parse_u64(fields[7], 10, &state_bytes) ||
        state_bytes != expected_state || code_size > SIZE_MAX ||
        max_input > SIZE_MAX) {
        return false;
    }
    if ((strcmp(fields[8], "absolute") != 0 &&
         strcmp(fields[8], "pie_relative") != 0) ||
        (strcmp(fields[9], "single") != 0 &&
         strcmp(fields[9], "blocks_x2") != 0) ||
        (strcmp(fields[13], "stable_direct") != 0 &&
         strcmp(fields[13], "transactional_copy") != 0)) {
        return false;
    }
    entry->pie_relative = strcmp(fields[8], "pie_relative") == 0;
    entry->blocks_x2 = strcmp(fields[9], "blocks_x2") == 0;
    entry->stable_direct = strcmp(fields[13], "stable_direct") == 0;
    entry->variant = strcmp(fields[5], "portable_c") == 0 ?
        LLMOPT_VARIANT_PORTABLE_C : LLMOPT_VARIANT_X86_64_OPTIMIZED;
    if (!llmopt_variant_available(
            entry->variant, entry->algorithm == LLMOPT_ALGO_SHA256_BLOCK)) {
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
            " substitution_region_ns=%" PRIu64
            " stable_direct_hits=%" PRIu64
            " portable_variant_hits=%" PRIu64
            " optimized_variant_hits=%" PRIu64
            " code_verifications=%" PRIu64
            " code_verification_failures=%" PRIu64
            " page_version_checks=%" PRIu64
            " page_version_mismatches=%" PRIu64
            " page_change_fallbacks=%" PRIu64
            " late_page_version_rejects=%" PRIu64
            " forced_code_changes=%" PRIu64
            " forced_code_restores=%" PRIu64
            " page_write_detection_failures=%" PRIu64 "\n",
            runtime.entry_count, runtime.attempts, runtime.guard_checks,
            runtime.hits, runtime.guarded_fallbacks,
            runtime.rechecks_after_fallback, runtime.code_rejects,
            runtime.state_rejects, runtime.memory_rejects,
            runtime.forced_rejects, runtime.unguarded_executions,
            runtime.baseline_region_count, runtime.baseline_region_ns,
            runtime.substitution_region_count, runtime.substitution_region_ns,
            runtime.stable_direct_hits, runtime.portable_variant_hits,
            runtime.optimized_variant_hits, runtime.code_verifications,
            runtime.code_verification_failures, runtime.page_version_checks,
            runtime.page_version_mismatches, runtime.page_change_fallbacks,
            runtime.late_page_version_rejects, runtime.forced_code_changes,
            runtime.forced_code_restores,
            runtime.page_write_detection_failures);
}

static void disable_map(const char *reason)
{
    runtime.enabled = false;
    runtime.entry_count = 0;
    fprintf(stderr, "LLMOPT disabled: %s\n", reason);
}

void llmopt_initialize(bool debugger_active, const char *guest_binary,
                       uint64_t guest_load_bias)
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
    runtime.force_code_change_once =
        g_strcmp0(getenv("QEMU_LLMOPT_FORCE_CODE_CHANGE_ONCE"), "1") == 0;
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
    if (strcmp(lines[0], "llmopt_dispatch_map.v2") != 0 ||
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
        if (parsed[i].pie_relative) {
            if (parsed[i].pc + guest_load_bias < parsed[i].pc) {
                disable_map("PIE entry address overflow");
                return;
            }
            parsed[i].runtime_pc = parsed[i].pc + guest_load_bias;
        } else {
            parsed[i].runtime_pc = parsed[i].pc;
        }
        for (size_t j = 0; j < i; j++) {
            if (parsed[i].runtime_pc == parsed[j].runtime_pc) {
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

static bool entry_bytes_reverify(LlmoptEntry *entry)
{
    g_autofree uint8_t *code = g_try_malloc(entry->code_size);
    uint8_t digest[32];
    size_t token_count = 0;
    bool matched;

    runtime.code_verifications++;
    entry->code_verified = false;
    if (!code ||
        !llmopt_page_version_snapshot(entry->runtime_pc, entry->code_size,
                                      code, entry->page_tokens,
                                      LLMOPT_MAX_CODE_PAGES, &token_count)) {
        entry->page_token_count = 0;
        runtime.code_verification_failures++;
        return false;
    }
    entry->page_token_count = token_count;
    sha256_buffer(code, entry->code_size, digest);
    matched = memcmp(digest, entry->code_sha256, sizeof(digest)) == 0;
    entry->code_verified = matched;
    if (!matched) {
        runtime.code_verification_failures++;
    }
    return matched;
}

static bool force_code_change(CPUState *cpu, LlmoptEntry *entry)
{
    uint8_t changed;

    if (!runtime.force_code_change_once || runtime.forced_code_change_fired ||
        runtime.attempts < 2) {
        return false;
    }
    runtime.forced_code_change_fired = true;
    runtime.forced_code_address = entry->runtime_pc + entry->code_size - 1;
    if (cpu_memory_rw_debug(cpu, runtime.forced_code_address,
                            &runtime.forced_code_original, 1, false) != 0) {
        return false;
    }
    changed = runtime.forced_code_original ^ 1;
    if (cpu_memory_rw_debug(cpu, runtime.forced_code_address,
                            &changed, 1, true) != 0) {
        return false;
    }
    runtime.forced_code_restore_pending = true;
    runtime.forced_code_changes++;
    return true;
}

static bool restore_forced_code_change(CPUState *cpu)
{
    if (runtime.forced_code_restore_pending &&
        cpu_memory_rw_debug(cpu, runtime.forced_code_address,
                            &runtime.forced_code_original, 1, true) == 0) {
        runtime.forced_code_restore_pending = false;
        runtime.forced_code_restores++;
        return true;
    }
    return false;
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
    uint8_t *input_host = NULL;
    uint8_t *state_host;
    uint32_t state[8] = { 0 };
    uint64_t blocks = entry->blocks_x2 ? env->xregs[2] : 1;
    uint64_t input_bytes;
    bool variant_ok = true;

    if (blocks == 0 || blocks > entry->max_input / sizeof(input)) {
        return false;
    }
    input_bytes = blocks * sizeof(input);
    if ((state_address & 3) || state_address + entry->state_bytes < state_address ||
        input_address + input_bytes < input_address ||
        ranges_overlap(state_address, entry->state_bytes,
                       input_address, input_bytes)) {
        return false;
    }
    state_host = lock_user(VERIFY_WRITE, state_address, entry->state_bytes, 1);
    if (entry->stable_direct) {
        input_host = lock_user(VERIFY_READ, input_address, input_bytes, 0);
    }
    if (!state_host || (entry->stable_direct && !input_host) ||
        (!entry->stable_direct &&
         copy_from_user(input, input_address, sizeof(input)) != 0)) {
        if (input_host) {
            unlock_user(input_host, input_address, 0);
        }
        if (state_host) {
            unlock_user(state_host, state_address, 0);
        }
        return false;
    }
    for (size_t i = 0; i < entry->state_bytes / 4; i++) {
        state[i] = ldl_le_p(state_host + i * 4);
    }
    if (entry->stable_direct) {
        if (entry->algorithm == LLMOPT_ALGO_MD5_BLOCK) {
            variant_ok = llmopt_variant_md5(entry->variant, state,
                                             input_host, blocks);
        } else if (entry->algorithm == LLMOPT_ALGO_SHA256_BLOCK) {
            variant_ok = llmopt_variant_sha256(entry->variant, state,
                                                input_host, blocks);
        } else {
            variant_ok = false;
        }
    } else {
        for (uint64_t block = 0; block < blocks; block++) {
            const uint8_t *current;
            if (block == 0) {
                current = input;
            } else {
                if (copy_from_user(input, input_address + block * sizeof(input),
                                   sizeof(input)) != 0) {
                    unlock_user(state_host, state_address, 0);
                    return false;
                }
                current = input;
            }
            if (entry->algorithm == LLMOPT_ALGO_MD5_BLOCK) {
                variant_ok = llmopt_variant_md5(entry->variant, state,
                                                 current, 1);
            } else if (entry->algorithm == LLMOPT_ALGO_SHA256_BLOCK) {
                variant_ok = llmopt_variant_sha256(entry->variant, state,
                                                    current, 1);
            } else {
                variant_ok = false;
            }
            if (!variant_ok) {
                break;
            }
        }
    }
    if (!variant_ok) {
        if (input_host) {
            unlock_user(input_host, input_address, 0);
        }
        unlock_user(state_host, state_address, 0);
        return false;
    }
    for (size_t i = 0; i < entry->state_bytes / 4; i++) {
        stl_le_p(state_host + i * 4, state[i]);
    }
    if (input_host) {
        unlock_user(input_host, input_address, 0);
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
    LlmoptEntry *entry = NULL;
    CPUARMState *env;
    TaskState *task;
    bool guards_passed = false;
    bool forced_code_change_now;
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
        if (runtime.entries[i].runtime_pc == pc) {
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
    forced_code_change_now = force_code_change(cpu, entry);
    if (entry->page_token_count == 0) {
        if (!entry_bytes_reverify(entry)) {
            restore_forced_code_change(cpu);
            runtime.code_rejects++;
            return guarded_fallback(pc, "exact_entry_bytes_initial");
        }
    } else {
        bool versions_match;

        runtime.page_version_checks++;
        versions_match = llmopt_page_versions_match(entry->page_tokens,
                                                     entry->page_token_count);
        if (forced_code_change_now && versions_match) {
            /* A forced write that misses QEMU's invalidation hook is RED. */
            runtime.page_write_detection_failures++;
            entry->code_verified = false;
            restore_forced_code_change(cpu);
            return guarded_fallback(pc, "forced_code_change_undetected");
        }
        if (!versions_match) {
            bool reverified;
            bool restored_and_reverified = false;

            runtime.page_version_mismatches++;
            entry->code_verified = false;
            reverified = entry_bytes_reverify(entry);
            if (!reverified) {
                runtime.code_rejects++;
            }
            if (restore_forced_code_change(cpu) && forced_code_change_now) {
                /*
                 * The changed bytes failed above.  Re-protect and verify the
                 * restored bytes now, but still execute baseline for this
                 * page-change call before re-enabling substitution.
                 */
                restored_and_reverified = entry_bytes_reverify(entry);
            }
            runtime.page_change_fallbacks++;
            return guarded_fallback(
                pc, restored_and_reverified ?
                    "forced_code_changed_restored_reverified" :
                    (reverified ? "code_page_changed_reverified" :
                                  "code_page_changed_mismatch"));
        }
    }
    restore_forced_code_change(cpu);
    if (!entry->code_verified) {
        runtime.code_rejects++;
        return guarded_fallback(pc, "exact_entry_bytes_unverified");
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
    /* Close the check-to-use window before reading or committing guest state. */
    runtime.page_version_checks++;
    if (!entry->code_verified ||
        !llmopt_page_versions_match(entry->page_tokens,
                                    entry->page_token_count)) {
        entry->code_verified = false;
        runtime.late_page_version_rejects++;
        return guarded_fallback(pc, "late_code_page_change");
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
    if (entry->variant == LLMOPT_VARIANT_PORTABLE_C) {
        runtime.portable_variant_hits++;
    } else {
        runtime.optimized_variant_hits++;
    }
    if (entry->stable_direct) {
        runtime.stable_direct_hits++;
    }
    if (runtime.trace) {
        fprintf(stderr,
                "LLMOPT_HIT pc=0x%" PRIx64 " catalog=%s verdict=%s"
                " variant=%s guard_checked=1 hit=%" PRIu64 "\n",
                (uint64_t)pc, entry->catalog_id, entry->verdict_id,
                entry->variant == LLMOPT_VARIANT_PORTABLE_C ?
                    "portable_c" : "x86_64_optimized",
                runtime.hits);
    }
    return LLMOPT_SUBSTITUTED;
}

#endif /* TARGET_AARCH64 */

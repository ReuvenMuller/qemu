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
#include "qemu/thread.h"
#include "exec/llmopt.h"
#include "exec/mmap-lock.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/page-protection.h"
#include "llmopt-variants.h"

#include <fenv.h>
#include <math.h>

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

void llmopt_cleanup(void)
{
}

LlmoptDispatchResult llmopt_try_dispatch(CPUState *cpu, vaddr pc)
{
    return LLMOPT_NOT_APPLICABLE;
}

LlmoptDispatchResult llmopt_run_pending_exclusive(CPUState *cpu)
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
    LLMOPT_ALGO_MEMCPY,
    LLMOPT_ALGO_LZ_MATCH_COPY,
    LLMOPT_ALGO_MEMSET,
    LLMOPT_ALGO_XXH64_STREAM,
    LLMOPT_ALGO_SHA256_STREAM,
    LLMOPT_ALGO_FP_SAMPLERATE,
} LlmoptAlgorithm;

typedef enum LlmoptIdentityState {
    LLMOPT_IDENTITY_PENDING = 0,
    LLMOPT_IDENTITY_MATCHED,
    LLMOPT_IDENTITY_MISMATCHED,
    LLMOPT_IDENTITY_CANCELLED,
} LlmoptIdentityState;

typedef enum LlmoptInvocationMode {
    LLMOPT_INVOKE_SINGLE_CPU = 0,
    LLMOPT_INVOKE_EXCLUSIVE_SECTION,
} LlmoptInvocationMode;

typedef struct LlmoptIdentityJob {
    QemuThread thread;
    char *guest_binary;
    char expected_guest_sha256[65];
    char *runtime_binary;
    char expected_runtime_sha256[65];
    bool verify_runtime;
    uint64_t test_delay_ms;
    int state;
    int cancel_requested;
} LlmoptIdentityJob;

typedef struct LlmoptEntry {
    LlmoptAlgorithm algorithm;
    LlmoptInvocationMode invocation_mode;
    LlmoptHostVariant variant;
    char catalog_id[32];
    char verdict_id[37];
    uint64_t pc;
    uint64_t runtime_pc;
    uint64_t authorized_return_pc;
    uint64_t runtime_return_pc;
    size_t code_size;
    uint8_t code_sha256[32];
    uint8_t implementation_sha256[32];
    uint8_t generated_code_sha256[32];
    uint8_t variant_admission_sha256[32];
    size_t max_input;
    size_t state_bytes;
    bool stable_direct;
    bool blocks_x2;
    bool lz_overlap;
    bool memset_shape;
    bool streaming_xxh64;
    bool streaming_sha256;
    bool fp_samplerate;
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
    bool test_probe_counter;
    uint64_t test_exclusive_hold_ms;
    uint64_t test_unprotected_probe_ms;
    bool forced_code_change_fired;
    bool forced_code_restore_pending;
    LlmoptIdentityJob identity_job;
    bool identity_thread_started;
    bool identity_thread_joined;
    bool identity_result_accounted;
    bool identity_activation_observed;
    bool baseline_region_active;
    bool sequence_region_active;
    bool pending_recheck;
    uint64_t baseline_return_pc;
    uint64_t baseline_start_ns;
    uint64_t sequence_return_pc;
    uint64_t sequence_start_ns;
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
    uint64_t sequence_region_count;
    uint64_t sequence_region_ns;
    uint64_t stable_direct_hits;
    uint64_t portable_variant_hits;
    uint64_t optimized_variant_hits;
    uint64_t bulk_variant_hits;
    uint64_t code_verifications;
    uint64_t code_verification_failures;
    uint64_t page_version_checks;
    uint64_t page_version_mismatches;
    uint64_t page_change_fallbacks;
    uint64_t late_page_version_rejects;
    uint64_t forced_code_changes;
    uint64_t forced_code_restores;
    uint64_t page_write_detection_failures;
    uint64_t guest_identity_checks;
    uint64_t guest_identity_failures;
    uint64_t guest_identity_matches;
    uint64_t guest_identity_cancellations;
    uint64_t identity_pending_fallbacks;
    uint64_t identity_mismatch_fallbacks;
    uint64_t identity_activation_observations;
    uint64_t runtime_identity_checks;
    uint64_t runtime_identity_failures;
    uint64_t runtime_identity_matches;
    uint64_t single_cpu_guard_rejects;
    uint64_t invocation_mode_refusals;
    uint64_t caller_pc_rejects;
    uint64_t exclusive_requests;
    uint64_t exclusive_entries;
    uint64_t exclusive_exits;
    uint64_t exclusive_recheck_fallbacks;
    uint64_t exclusive_contentions;
    uint64_t exclusive_wait_events;
    uint64_t exclusive_overlap_failures;
    uint64_t negative_control_overlaps;
    uint64_t exclusive_wait_ns;
    uint64_t exclusive_hold_ns;
    uint64_t exclusive_max_wait_ns;
    uint64_t exclusive_max_hold_ns;
} LlmoptRuntime;

static LlmoptRuntime runtime;
static __thread LlmoptEntry *exclusive_pending_entry;
static __thread uint64_t exclusive_pending_start_ns;

static uint64_t now_ns(void);
static bool another_guest_cpu_running(CPUState *cpu);

static bool observe_other_cpu_running(CPUState *cpu, uint64_t duration_ms)
{
    bool observed = false;

    for (uint64_t elapsed = 0; elapsed < duration_ms; elapsed++) {
        observed |= another_guest_cpu_running(cpu);
        g_usleep(1000);
    }
    return observed;
}

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

static bool identity_cancelled(const LlmoptIdentityJob *job)
{
    return qatomic_load_acquire(&job->cancel_requested);
}

static LlmoptIdentityState file_identity(LlmoptIdentityJob *job,
                                         const char *path,
                                         const char *expected)
{
    g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t buffer[65536];
    FILE *stream;
    size_t length;

    for (uint64_t elapsed = 0; elapsed < job->test_delay_ms; elapsed++) {
        if (identity_cancelled(job)) {
            return LLMOPT_IDENTITY_CANCELLED;
        }
        g_usleep(1000);
    }
    if (identity_cancelled(job)) {
        return LLMOPT_IDENTITY_CANCELLED;
    }
    if (!checksum || !path || !(stream = fopen(path, "rb"))) {
        return LLMOPT_IDENTITY_MISMATCHED;
    }
    while ((length = fread(buffer, 1, sizeof(buffer), stream)) > 0) {
        if (identity_cancelled(job)) {
            fclose(stream);
            return LLMOPT_IDENTITY_CANCELLED;
        }
        g_checksum_update(checksum, buffer, length);
    }
    if (identity_cancelled(job)) {
        fclose(stream);
        return LLMOPT_IDENTITY_CANCELLED;
    }
    if (ferror(stream)) {
        fclose(stream);
        return LLMOPT_IDENTITY_MISMATCHED;
    }
    fclose(stream);
    return strcmp(g_checksum_get_string(checksum), expected) == 0 ?
        LLMOPT_IDENTITY_MATCHED : LLMOPT_IDENTITY_MISMATCHED;
}

static void *guest_identity_worker(void *opaque)
{
    LlmoptIdentityJob *job = opaque;
    LlmoptIdentityState result = file_identity(
        job, job->guest_binary, job->expected_guest_sha256);

    if (result == LLMOPT_IDENTITY_MATCHED && job->verify_runtime) {
        result = file_identity(job, job->runtime_binary,
                               job->expected_runtime_sha256);
    }

    qatomic_store_release(&job->state, result);
    return NULL;
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
    } else if (strcmp(catalog, "memory.memcpy") == 0) {
        *algo = LLMOPT_ALGO_MEMCPY;
        *expected_state = 0;
    } else if (strcmp(catalog, "codec.lz.match_copy") == 0) {
        *algo = LLMOPT_ALGO_LZ_MATCH_COPY;
        *expected_state = 0;
    } else if (strcmp(catalog, "memory.memset") == 0) {
        *algo = LLMOPT_ALGO_MEMSET;
        *expected_state = 0;
    } else if (strcmp(catalog, "digest.xxh64.streaming") == 0) {
        *algo = LLMOPT_ALGO_XXH64_STREAM;
        *expected_state = 88;
    } else if (strcmp(catalog, "digest.sha256.streaming") == 0) {
        *algo = LLMOPT_ALGO_SHA256_STREAM;
        *expected_state = 112;
    } else if (strcmp(catalog, "fp.samplerate.sinc_mono") == 0) {
        *algo = LLMOPT_ALGO_FP_SAMPLERATE;
        *expected_state = 80;
    } else {
        return false;
    }
    return true;
}

static LlmoptVariantAlgorithm variant_algorithm(LlmoptAlgorithm algorithm)
{
    switch (algorithm) {
    case LLMOPT_ALGO_XXH64:
        return LLMOPT_VARIANT_ALGO_XXH64;
    case LLMOPT_ALGO_SHA256_BLOCK:
        return LLMOPT_VARIANT_ALGO_SHA256;
    case LLMOPT_ALGO_MD5_BLOCK:
        return LLMOPT_VARIANT_ALGO_MD5;
    case LLMOPT_ALGO_CRC32:
        return LLMOPT_VARIANT_ALGO_CRC32;
    case LLMOPT_ALGO_ADLER32:
        return LLMOPT_VARIANT_ALGO_ADLER32;
    case LLMOPT_ALGO_MEMCPY:
        return LLMOPT_VARIANT_ALGO_MEMCPY;
    case LLMOPT_ALGO_LZ_MATCH_COPY:
        return LLMOPT_VARIANT_ALGO_LZ_MATCH_COPY;
    case LLMOPT_ALGO_MEMSET:
        return LLMOPT_VARIANT_ALGO_MEMSET;
    case LLMOPT_ALGO_XXH64_STREAM:
        return LLMOPT_VARIANT_ALGO_XXH64_STREAM;
    case LLMOPT_ALGO_SHA256_STREAM:
        return LLMOPT_VARIANT_ALGO_SHA256_STREAM;
    case LLMOPT_ALGO_FP_SAMPLERATE:
        return LLMOPT_VARIANT_ALGO_FP_SAMPLERATE;
    default:
        g_assert_not_reached();
    }
}

static bool parse_entry_line(const char *line, LlmoptEntry *entry, bool v3)
{
    g_auto(GStrv) fields = g_strsplit(line, "\t", -1);
    uint64_t pc, code_size, max_input, state_bytes, return_pc = 0;
    size_t expected_state;

    size_t field_count = g_strv_length(fields);

    if (field_count != (v3 ? 16 : 14) ||
        !algorithm_for_catalog(fields[0], &entry->algorithm, &expected_state) ||
        strlen(fields[0]) >= sizeof(entry->catalog_id) ||
        strlen(fields[1]) != 36 || strlen(fields[5]) == 0 ||
        (strcmp(fields[5], "portable_c") != 0 &&
         strcmp(fields[5], "x86_64_optimized") != 0 &&
         strcmp(fields[5], "bulk_c") != 0) ||
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
    if (v3 &&
        (strcmp(fields[14], "exclusive_section.v1") != 0 ||
         !parse_u64(fields[15], 16, &return_pc) || !return_pc ||
         strcmp(fields[0], "digest.xxh64.streaming") != 0)) {
        return false;
    }
    if ((strcmp(fields[8], "absolute") != 0 &&
         strcmp(fields[8], "pie_relative") != 0) ||
        (strcmp(fields[9], "single") != 0 &&
         strcmp(fields[9], "blocks_x2") != 0 &&
         strcmp(fields[9], "lz_overlap") != 0 &&
         strcmp(fields[9], "memset") != 0 &&
         strcmp(fields[9], "streaming_xxh64") != 0 &&
         strcmp(fields[9], "streaming_sha256") != 0 &&
         strcmp(fields[9], "fp_samplerate") != 0) ||
        (strcmp(fields[13], "stable_direct") != 0 &&
         strcmp(fields[13], "transactional_copy") != 0)) {
        return false;
    }
    entry->pie_relative = strcmp(fields[8], "pie_relative") == 0;
    entry->blocks_x2 = strcmp(fields[9], "blocks_x2") == 0;
    entry->lz_overlap = strcmp(fields[9], "lz_overlap") == 0;
    entry->memset_shape = strcmp(fields[9], "memset") == 0;
    entry->streaming_xxh64 = strcmp(fields[9], "streaming_xxh64") == 0;
    entry->streaming_sha256 = strcmp(fields[9], "streaming_sha256") == 0;
    entry->fp_samplerate = strcmp(fields[9], "fp_samplerate") == 0;
    entry->stable_direct = strcmp(fields[13], "stable_direct") == 0;
    if (entry->lz_overlap != (entry->algorithm == LLMOPT_ALGO_LZ_MATCH_COPY) ||
        (entry->lz_overlap && entry->stable_direct)) {
        return false;
    }
    if (entry->memset_shape != (entry->algorithm == LLMOPT_ALGO_MEMSET) ||
        (entry->memset_shape && entry->stable_direct)) {
        return false;
    }
    if (entry->streaming_xxh64 !=
            (entry->algorithm == LLMOPT_ALGO_XXH64_STREAM)) {
        return false;
    }
    if (entry->streaming_sha256 !=
            (entry->algorithm == LLMOPT_ALGO_SHA256_STREAM)) {
        return false;
    }
    if (entry->fp_samplerate !=
            (entry->algorithm == LLMOPT_ALGO_FP_SAMPLERATE) ||
        (entry->fp_samplerate && !entry->stable_direct)) {
        return false;
    }
    if (strcmp(fields[5], "portable_c") == 0) {
        entry->variant = LLMOPT_VARIANT_PORTABLE_C;
    } else if (strcmp(fields[5], "x86_64_optimized") == 0) {
        entry->variant = LLMOPT_VARIANT_X86_64_OPTIMIZED;
    } else if (strcmp(fields[5], "bulk_c") == 0) {
        entry->variant = LLMOPT_VARIANT_BULK_C;
    } else {
        return false;
    }
    if (!llmopt_variant_available(entry->variant,
                                  variant_algorithm(entry->algorithm))) {
        return false;
    }
    g_strlcpy(entry->catalog_id, fields[0], sizeof(entry->catalog_id));
    g_strlcpy(entry->verdict_id, fields[1], sizeof(entry->verdict_id));
    entry->pc = pc;
    entry->invocation_mode = v3 ? LLMOPT_INVOKE_EXCLUSIVE_SECTION :
                                  LLMOPT_INVOKE_SINGLE_CPU;
    entry->authorized_return_pc = return_pc;
    entry->code_size = code_size;
    entry->max_input = max_input;
    entry->state_bytes = state_bytes;
    return true;
}

static LlmoptIdentityState identity_state_acquire(void)
{
    return qatomic_load_acquire(&runtime.identity_job.state);
}

static void identity_account_result(void)
{
    LlmoptIdentityState state;

    if (!runtime.identity_thread_started || runtime.identity_result_accounted) {
        return;
    }
    state = identity_state_acquire();
    if (state == LLMOPT_IDENTITY_PENDING) {
        return;
    }
    runtime.identity_result_accounted = true;
    if (state == LLMOPT_IDENTITY_MATCHED) {
        runtime.guest_identity_matches++;
        if (runtime.identity_job.verify_runtime) {
            runtime.runtime_identity_matches++;
        }
    } else if (state == LLMOPT_IDENTITY_MISMATCHED) {
        runtime.guest_identity_failures++;
        if (runtime.identity_job.verify_runtime) {
            runtime.runtime_identity_failures++;
        }
    } else if (state == LLMOPT_IDENTITY_CANCELLED) {
        runtime.guest_identity_cancellations++;
    }
}

void llmopt_cleanup(void)
{
    if (!runtime.identity_thread_started || runtime.identity_thread_joined) {
        return;
    }
    if (identity_state_acquire() == LLMOPT_IDENTITY_PENDING) {
        qatomic_store_release(&runtime.identity_job.cancel_requested, true);
    }
    qemu_thread_join(&runtime.identity_job.thread);
    runtime.identity_thread_joined = true;
    identity_account_result();
    g_clear_pointer(&runtime.identity_job.guest_binary, g_free);
    g_clear_pointer(&runtime.identity_job.runtime_binary, g_free);
}

void llmopt_report(void)
{
    identity_account_result();
    if ((!runtime.enabled && runtime.guest_identity_failures == 0) ||
        !runtime.report_enabled || runtime.reported) {
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
            " sequence_region_count=%" PRIu64
            " sequence_region_ns=%" PRIu64
            " stable_direct_hits=%" PRIu64
            " portable_variant_hits=%" PRIu64
            " optimized_variant_hits=%" PRIu64
            " bulk_variant_hits=%" PRIu64
            " code_verifications=%" PRIu64
            " code_verification_failures=%" PRIu64
            " page_version_checks=%" PRIu64
            " page_version_mismatches=%" PRIu64
            " page_change_fallbacks=%" PRIu64
            " late_page_version_rejects=%" PRIu64
            " forced_code_changes=%" PRIu64
            " forced_code_restores=%" PRIu64
            " page_write_detection_failures=%" PRIu64
            " guest_identity_checks=%" PRIu64
            " guest_identity_failures=%" PRIu64
            " guest_identity_matches=%" PRIu64
            " guest_identity_cancellations=%" PRIu64
            " identity_pending_fallbacks=%" PRIu64
            " identity_mismatch_fallbacks=%" PRIu64
            " identity_activation_observations=%" PRIu64
            " runtime_identity_checks=%" PRIu64
            " runtime_identity_failures=%" PRIu64
            " runtime_identity_matches=%" PRIu64
            " single_cpu_guard_rejects=%" PRIu64
            " invocation_mode_refusals=%" PRIu64
            " caller_pc_rejects=%" PRIu64
            " exclusive_requests=%" PRIu64
            " exclusive_entries=%" PRIu64
            " exclusive_exits=%" PRIu64
            " exclusive_recheck_fallbacks=%" PRIu64
            " exclusive_contentions=%" PRIu64
            " exclusive_wait_events=%" PRIu64
            " exclusive_overlap_failures=%" PRIu64
            " negative_control_overlaps=%" PRIu64
            " exclusive_wait_ns=%" PRIu64
            " exclusive_hold_ns=%" PRIu64
            " exclusive_max_wait_ns=%" PRIu64
            " exclusive_max_hold_ns=%" PRIu64
            " identity_state=%d\n",
            runtime.entry_count, runtime.attempts, runtime.guard_checks,
            runtime.hits, runtime.guarded_fallbacks,
            runtime.rechecks_after_fallback, runtime.code_rejects,
            runtime.state_rejects, runtime.memory_rejects,
            runtime.forced_rejects, runtime.unguarded_executions,
            runtime.baseline_region_count, runtime.baseline_region_ns,
            runtime.substitution_region_count, runtime.substitution_region_ns,
            runtime.sequence_region_count, runtime.sequence_region_ns,
            runtime.stable_direct_hits, runtime.portable_variant_hits,
            runtime.optimized_variant_hits, runtime.bulk_variant_hits,
            runtime.code_verifications,
            runtime.code_verification_failures, runtime.page_version_checks,
            runtime.page_version_mismatches, runtime.page_change_fallbacks,
            runtime.late_page_version_rejects, runtime.forced_code_changes,
            runtime.forced_code_restores,
            runtime.page_write_detection_failures,
            runtime.guest_identity_checks, runtime.guest_identity_failures,
            runtime.guest_identity_matches,
            runtime.guest_identity_cancellations,
            runtime.identity_pending_fallbacks,
            runtime.identity_mismatch_fallbacks,
            runtime.identity_activation_observations,
            runtime.runtime_identity_checks,
            runtime.runtime_identity_failures,
            runtime.runtime_identity_matches,
            runtime.single_cpu_guard_rejects,
            runtime.invocation_mode_refusals,
            runtime.caller_pc_rejects,
            runtime.exclusive_requests,
            runtime.exclusive_entries,
            runtime.exclusive_exits,
            runtime.exclusive_recheck_fallbacks,
            runtime.exclusive_contentions,
            runtime.exclusive_wait_events,
            runtime.exclusive_overlap_failures,
            runtime.negative_control_overlaps,
            runtime.exclusive_wait_ns,
            runtime.exclusive_hold_ns,
            runtime.exclusive_max_wait_ns,
            runtime.exclusive_max_hold_ns,
            runtime.identity_thread_started ? identity_state_acquire() : -1);
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
    const char *test_delay = getenv("QEMU_LLMOPT_TEST_HASH_DELAY_MS");
    const char *test_hold = getenv("QEMU_LLMOPT_TEST_EXCLUSIVE_HOLD_MS");
    const char *test_unprotected =
        getenv("QEMU_LLMOPT_TEST_UNPROTECTED_PROBE_MS");
    g_autofree char *contents = NULL;
    g_autofree char *guest_binary_copy = NULL;
    g_auto(GStrv) lines = NULL;
    gsize length = 0;
    uint64_t declared_count;
    uint64_t test_delay_ms = 0;
    uint8_t guest_sha256[32];
    uint8_t runtime_sha256[32];
    bool v3;
    size_t header_lines;
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
    runtime.test_probe_counter =
        g_strcmp0(getenv("QEMU_LLMOPT_TEST_PROBE_COUNTER_X3"), "1") == 0;
    if (g_strcmp0(getenv("QEMU_LLMOPT"), "1") != 0) {
        return;
    }
    if (test_delay &&
        (!parse_u64(test_delay, 10, &test_delay_ms) ||
         test_delay_ms > 60000)) {
        disable_map("invalid background-hash test delay");
        return;
    }
    if ((test_hold && (!parse_u64(test_hold, 10,
                                  &runtime.test_exclusive_hold_ms) ||
                       runtime.test_exclusive_hold_ms > 5000)) ||
        (test_unprotected &&
         (!parse_u64(test_unprotected, 10,
                     &runtime.test_unprotected_probe_ms) ||
          runtime.test_unprotected_probe_ms > 5000))) {
        disable_map("invalid exclusive audit delay");
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
    v3 = strcmp(lines[0], "llmopt_dispatch_map.v3") == 0;
    header_lines = v3 ? 5 : 4;
    if ((!v3 && strcmp(lines[0], "llmopt_dispatch_map.v2") != 0) ||
        !g_str_has_prefix(lines[1], "guest_sha256\t") ||
        !parse_sha256(lines[1] + strlen("guest_sha256\t"), guest_sha256) ||
        !g_str_has_prefix(lines[2], "qemu_validation_sha256\t") ||
        strcmp(lines[2] + strlen("qemu_validation_sha256\t"),
               LLMOPT_VALIDATION_QEMU_SHA256) != 0 ||
        (v3 && (!g_str_has_prefix(lines[3], "qemu_runtime_sha256\t") ||
                !parse_sha256(lines[3] + strlen("qemu_runtime_sha256\t"),
                              runtime_sha256))) ||
        !g_str_has_prefix(lines[header_lines - 1], "entry_count\t") ||
        !parse_u64(lines[header_lines - 1] + strlen("entry_count\t"),
                   10, &declared_count) ||
        declared_count == 0 || declared_count > LLMOPT_MAX_ENTRIES ||
        g_strv_length(lines) != declared_count + header_lines + 1 ||
        lines[declared_count + header_lines][0] != '\0') {
        disable_map("map header or validation-QEMU identity rejected");
        return;
    }
    for (size_t i = 0; i < declared_count; i++) {
        if (!parse_entry_line(lines[i + header_lines], &parsed[i], v3)) {
            disable_map("unsupported or malformed entry row");
            return;
        }
        if (parsed[i].pie_relative) {
            if (parsed[i].pc + guest_load_bias < parsed[i].pc) {
                disable_map("PIE entry address overflow");
                return;
            }
            parsed[i].runtime_pc = parsed[i].pc + guest_load_bias;
            if (parsed[i].authorized_return_pc + guest_load_bias <
                parsed[i].authorized_return_pc) {
                disable_map("PIE return address overflow");
                return;
            }
            parsed[i].runtime_return_pc =
                parsed[i].authorized_return_pc + guest_load_bias;
        } else {
            parsed[i].runtime_pc = parsed[i].pc;
            parsed[i].runtime_return_pc = parsed[i].authorized_return_pc;
        }
        for (size_t j = 0; j < i; j++) {
            if (parsed[i].runtime_pc == parsed[j].runtime_pc) {
                disable_map("ambiguous duplicate entry PC");
                return;
            }
        }
    }
    guest_binary_copy = g_strdup(guest_binary);
    if (!guest_binary_copy) {
        disable_map("guest binary path unavailable");
        return;
    }
    memcpy(runtime.entries, parsed, declared_count * sizeof(parsed[0]));
    runtime.identity_job.guest_binary =
        g_steal_pointer(&guest_binary_copy);
    if (v3) {
        runtime.identity_job.runtime_binary = g_strdup("/proc/self/exe");
        if (!runtime.identity_job.runtime_binary) {
            disable_map("runtime binary path unavailable");
            return;
        }
        g_strlcpy(runtime.identity_job.expected_runtime_sha256,
                  lines[3] + strlen("qemu_runtime_sha256\t"),
                  sizeof(runtime.identity_job.expected_runtime_sha256));
        runtime.identity_job.verify_runtime = true;
        runtime.runtime_identity_checks++;
        if (file_identity(&runtime.identity_job,
                          runtime.identity_job.runtime_binary,
                          runtime.identity_job.expected_runtime_sha256) !=
            LLMOPT_IDENTITY_MATCHED) {
            runtime.runtime_identity_failures++;
            g_clear_pointer(&runtime.identity_job.guest_binary, g_free);
            g_clear_pointer(&runtime.identity_job.runtime_binary, g_free);
            disable_map("runtime QEMU identity rejected");
            return;
        }
        runtime.runtime_identity_matches++;
        /* The background job now needs only the exact guest identity. */
        runtime.identity_job.verify_runtime = false;
    }
    g_strlcpy(runtime.identity_job.expected_guest_sha256,
              lines[1] + strlen("guest_sha256\t"),
              sizeof(runtime.identity_job.expected_guest_sha256));
    runtime.identity_job.test_delay_ms = test_delay_ms;
    qatomic_set(&runtime.identity_job.state, LLMOPT_IDENTITY_PENDING);
    qatomic_set(&runtime.identity_job.cancel_requested, false);
    runtime.entry_count = declared_count;
    runtime.enabled = true;
    atexit(llmopt_report);
    atexit(llmopt_cleanup);
    qemu_thread_create(&runtime.identity_job.thread, "llmopt-identity",
                       guest_identity_worker, &runtime.identity_job,
                       QEMU_THREAD_JOINABLE);
    runtime.identity_thread_started = true;
    runtime.guest_identity_checks++;
    if (runtime.trace) {
        fprintf(stderr,
                "LLMOPT_MAP_READY entries=%zu immutable=1 identity=pending\n",
                runtime.entry_count);
    }
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

static LlmoptIdentityState guest_identity_activation_state(void)
{
    LlmoptIdentityState state = identity_state_acquire();

    if (state != LLMOPT_IDENTITY_PENDING) {
        identity_account_result();
    }
    if (state == LLMOPT_IDENTITY_MATCHED &&
        !runtime.identity_activation_observed) {
        runtime.identity_activation_observed = true;
        runtime.identity_activation_observations++;
        if (runtime.trace) {
            fprintf(stderr, "LLMOPT_IDENTITY_ACTIVATED matched=1\n");
        }
    }
    return state;
}

static bool force_code_change(CPUState *cpu, LlmoptEntry *entry)
{
    uint8_t changed;

    if (!runtime.force_code_change_once || runtime.forced_code_change_fired ||
        runtime.attempts < 2 || entry->page_token_count == 0) {
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
    g_autofree uint8_t *copied_input = NULL;
    uint8_t empty_input = 0;
    uint8_t *input = NULL;
    uint64_t result;
    uint32_t result32;

    if (length > entry->max_input || length > SIZE_MAX ||
        address + length < address) {
        return false;
    }
    if (entry->stable_direct) {
        input = length ? lock_user(VERIFY_READ, address, length, 0) : &empty_input;
    } else {
        copied_input = copy_input(address, length, entry->max_input);
        input = copied_input;
    }
    if (!input) {
        return false;
    }
    switch (entry->algorithm) {
    case LLMOPT_ALGO_XXH64:
        if (!llmopt_variant_xxh64(entry->variant, input, length, initial,
                                  &result)) {
            goto fail;
        }
        break;
    case LLMOPT_ALGO_CRC32:
        if (!llmopt_variant_crc32(entry->variant, input, length,
                                  (uint32_t)initial, &result32)) {
            goto fail;
        }
        result = result32;
        break;
    case LLMOPT_ALGO_ADLER32:
        if (!llmopt_variant_adler32(entry->variant, input, length,
                                    (uint32_t)initial, &result32)) {
            goto fail;
        }
        result = result32;
        break;
    default:
        goto fail;
    }
    if (entry->stable_direct && length) {
        unlock_user(input, address, 0);
    }
    env->xregs[0] = result;
    env->pc = env->xregs[30];
    return true;

fail:
    if (entry->stable_direct && length) {
        unlock_user(input, address, 0);
    }
    return false;
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

static bool substitute_memcpy(CPUARMState *env, const LlmoptEntry *entry)
{
    uint64_t destination_address = env->xregs[0];
    uint64_t source_address = env->xregs[1];
    uint64_t length = env->xregs[2];
    g_autofree uint8_t *copied_input = NULL;
    uint8_t *source = NULL;
    uint8_t *destination = NULL;

    if (length > entry->max_input || length > SIZE_MAX ||
        destination_address + length < destination_address ||
        source_address + length < source_address ||
        ranges_overlap(destination_address, length, source_address, length)) {
        return false;
    }
    if (length == 0) {
        env->pc = env->xregs[30];
        return true;
    }
    destination = lock_user(VERIFY_WRITE, destination_address, length, 1);
    if (entry->stable_direct) {
        source = lock_user(VERIFY_READ, source_address, length, 0);
    } else {
        copied_input = copy_input(source_address, length, entry->max_input);
        source = copied_input;
    }
    if (!destination || !source ||
        !llmopt_variant_memcpy(entry->variant, destination, source, length)) {
        if (entry->stable_direct && source) {
            unlock_user(source, source_address, 0);
        }
        if (destination) {
            unlock_user(destination, destination_address, 0);
        }
        return false;
    }
    if (entry->stable_direct) {
        unlock_user(source, source_address, 0);
    }
    unlock_user(destination, destination_address, length);
    env->xregs[0] = destination_address;
    env->pc = env->xregs[30];
    return true;
}

static bool substitute_lz_match_copy(CPUARMState *env,
                                     const LlmoptEntry *entry)
{
    uint64_t output_address = env->xregs[0];
    uint64_t length = env->xregs[1];
    uint64_t distance = env->xregs[2];
    uint64_t history_address;
    uint64_t total;
    size_t history_length;
    g_autofree uint8_t *scratch = NULL;
    uint8_t *output = NULL;

    if (!distance || output_address < distance ||
        length > SIZE_MAX || distance > SIZE_MAX ||
        length > entry->max_input || distance > entry->max_input ||
        length > entry->max_input - distance ||
        output_address + length < output_address) {
        return false;
    }
    if (length == 0) {
        env->pc = env->xregs[30];
        return true;
    }
    history_address = output_address - distance;
    total = distance + length;
    history_length = MIN((uint64_t)length, distance);
    scratch = g_try_malloc((size_t)total);
    if (!scratch ||
        copy_from_user(scratch, history_address, history_length) != 0) {
        return false;
    }
    output = lock_user(VERIFY_WRITE, output_address, length, 1);
    if (!output ||
        !llmopt_variant_lz_match_copy(entry->variant,
                                      scratch + distance, length, distance)) {
        if (output) {
            unlock_user(output, output_address, 0);
        }
        return false;
    }
    memcpy(output, scratch + distance, length);
    unlock_user(output, output_address, length);
    env->pc = env->xregs[30];
    return true;
}

static bool substitute_memset(CPUARMState *env, const LlmoptEntry *entry)
{
    uint64_t output_address = env->xregs[0];
    uint8_t value = env->xregs[1];
    uint64_t length = env->xregs[2];
    g_autofree uint8_t *scratch = NULL;
    uint8_t *output = NULL;

    if (length > entry->max_input || length > SIZE_MAX ||
        output_address + length < output_address) {
        return false;
    }
    if (length == 0) {
        env->xregs[0] = output_address;
        env->pc = env->xregs[30];
        return true;
    }
    scratch = g_try_malloc(length);
    output = lock_user(VERIFY_WRITE, output_address, length, 1);
    if (!scratch || !output ||
        !llmopt_variant_memset(entry->variant, scratch, value, length)) {
        if (output) {
            unlock_user(output, output_address, 0);
        }
        return false;
    }
    memcpy(output, scratch, length);
    unlock_user(output, output_address, length);
    env->xregs[0] = output_address;
    env->pc = env->xregs[30];
    return true;
}

static bool substitute_xxh64_stream(CPUARMState *env,
                                    const LlmoptEntry *entry)
{
    uint64_t state_address = env->xregs[0];
    uint64_t input_address = env->xregs[1];
    uint64_t length = env->xregs[2];
    uint8_t local_state[88] __attribute__((aligned(8)));
    g_autofree uint8_t *copied_input = NULL;
    uint8_t *input = NULL;
    uint8_t *state = NULL;

    if ((state_address & 7) || length > entry->max_input ||
        length > SIZE_MAX || state_address + sizeof(local_state) < state_address ||
        input_address + length < input_address ||
        ranges_overlap(state_address, sizeof(local_state), input_address, length)) {
        return false;
    }
    state = lock_user(VERIFY_WRITE, state_address, sizeof(local_state), 1);
    if (!state) {
        return false;
    }
    memcpy(local_state, state, sizeof(local_state));
    if (length) {
        if (entry->stable_direct) {
            input = lock_user(VERIFY_READ, input_address, length, 0);
        } else {
            copied_input = copy_input(input_address, length, entry->max_input);
            input = copied_input;
        }
        if (!input) {
            unlock_user(state, state_address, 0);
            return false;
        }
    }
    if (!llmopt_variant_xxh64_stream(entry->variant, local_state,
                                     input, length)) {
        if (entry->stable_direct && input) {
            unlock_user(input, input_address, 0);
        }
        unlock_user(state, state_address, 0);
        return false;
    }
    if (entry->stable_direct && input) {
        unlock_user(input, input_address, 0);
    }
    memcpy(state, local_state, sizeof(local_state));
    unlock_user(state, state_address, sizeof(local_state));
    env->xregs[0] = 0;
    env->pc = env->xregs[30];
    return true;
}

static bool substitute_sha256_stream(CPUARMState *env,
                                     const LlmoptEntry *entry)
{
    uint64_t state_address = env->xregs[0];
    uint64_t input_address = env->xregs[1];
    uint64_t length = env->xregs[2];
    uint8_t local_state[112] __attribute__((aligned(8)));
    g_autofree uint8_t *copied_input = NULL;
    uint8_t *input = NULL;
    uint8_t *state;

    if ((state_address & 3) || length > entry->max_input || length > SIZE_MAX ||
        state_address + sizeof(local_state) < state_address ||
        input_address + length < input_address ||
        ranges_overlap(state_address, sizeof(local_state), input_address, length)) {
        return false;
    }
    state = lock_user(VERIFY_WRITE, state_address, sizeof(local_state), 1);
    if (!state) {
        return false;
    }
    memcpy(local_state, state, sizeof(local_state));
    if (length) {
        if (entry->stable_direct) {
            input = lock_user(VERIFY_READ, input_address, length, 0);
        } else {
            copied_input = copy_input(input_address, length, entry->max_input);
            input = copied_input;
        }
        if (!input) {
            unlock_user(state, state_address, 0);
            return false;
        }
    }
    if (!llmopt_variant_sha256_stream(entry->variant, local_state,
                                      input, length)) {
        if (entry->stable_direct && input) {
            unlock_user(input, input_address, 0);
        }
        unlock_user(state, state_address, 0);
        return false;
    }
    if (entry->stable_direct && input) {
        unlock_user(input, input_address, 0);
    }
    memcpy(state, local_state, sizeof(local_state));
    unlock_user(state, state_address, sizeof(local_state));
    env->xregs[0] = 1;
    env->pc = env->xregs[30];
    return true;
}

typedef struct LlmoptSamplerateStateAdapter {
    void *vt;
    double last_ratio, last_position;
    int32_t error, channels, mode, padding;
    void *callback_func, *user_callback_data;
    int64_t saved_frames;
    const float *saved_data;
    void *private_data;
} LlmoptSamplerateStateAdapter;

typedef struct LlmoptSamplerateDataAdapter {
    const float *data_in;
    float *data_out;
    int64_t input_frames, output_frames;
    int64_t input_frames_used, output_frames_gen;
    int32_t end_of_input, padding;
    double src_ratio;
} LlmoptSamplerateDataAdapter;

typedef struct LlmoptSincFilterAdapter {
    int32_t sinc_magic_marker, padding;
    int64_t in_count, in_used, out_count, out_gen;
    int32_t coeff_half_len, index_inc;
    double src_ratio, input_index;
    const float *coeffs;
    int32_t b_current, b_end, b_real_end, b_len;
    double left_calc[128], right_calc[128];
    float *buffer;
} LlmoptSincFilterAdapter;

_Static_assert(sizeof(LlmoptSamplerateStateAdapter) == 80,
               "pinned SRC_STATE adapter layout");
_Static_assert(sizeof(LlmoptSamplerateDataAdapter) == 64,
               "pinned SRC_DATA adapter layout");
_Static_assert(sizeof(LlmoptSincFilterAdapter) == 2144,
               "pinned SINC_FILTER adapter layout");

static bool fp_float_domain_ok(const float *values, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (values[i] != 0.0f && !isnormal(values[i])) {
            return false;
        }
    }
    return true;
}

static bool fp_double_domain_ok(double value)
{
    return value == 0.0 || isnormal(value);
}

static bool substitute_fp_samplerate(CPUARMState *env,
                                     const LlmoptEntry *entry)
{
    uint64_t state_address = env->xregs[0];
    uint64_t data_address = env->xregs[1];
    uint64_t filter_address, input_address, output_address;
    uint64_t coeff_address, buffer_address;
    uint8_t local_state_bytes[80] __attribute__((aligned(8)));
    uint8_t local_data_bytes[64] __attribute__((aligned(8)));
    uint8_t local_filter_bytes[2144] __attribute__((aligned(8)));
    LlmoptSamplerateStateAdapter *local_state =
        (LlmoptSamplerateStateAdapter *)local_state_bytes;
    LlmoptSamplerateDataAdapter *local_data =
        (LlmoptSamplerateDataAdapter *)local_data_bytes;
    LlmoptSincFilterAdapter *local_filter =
        (LlmoptSincFilterAdapter *)local_filter_bytes;
    uint8_t *state = NULL, *data = NULL, *filter = NULL;
    float *input = NULL, *coefficients = NULL;
    float *guest_buffer = NULL, *guest_output = NULL;
    g_autofree float *scratch_buffer = NULL;
    g_autofree float *scratch_output = NULL;
    size_t input_count, output_count, coefficient_count, buffer_count;
    size_t input_bytes, output_bytes, coefficient_bytes, buffer_bytes;
    size_t committed_output_bytes = 0;
    fenv_t saved_fenv;
    int host_exceptions = 0;
    bool variant_ok = false, success = false;

    if (vfp_get_fpcr(env) != 0 || fegetround() != FE_TONEAREST ||
        (state_address & 7) || (data_address & 7) ||
        state_address + sizeof(local_state_bytes) < state_address ||
        data_address + sizeof(local_data_bytes) < data_address ||
        ranges_overlap(state_address, sizeof(local_state_bytes),
                       data_address, sizeof(local_data_bytes))) {
        return false;
    }
    state = lock_user(VERIFY_WRITE, state_address,
                      sizeof(local_state_bytes), 1);
    data = lock_user(VERIFY_WRITE, data_address,
                     sizeof(local_data_bytes), 1);
    if (!state || !data) {
        goto done;
    }
    memcpy(local_state_bytes, state, sizeof(local_state_bytes));
    memcpy(local_data_bytes, data, sizeof(local_data_bytes));
    filter_address = (uintptr_t)local_state->private_data;
    input_address = (uintptr_t)local_data->data_in;
    output_address = (uintptr_t)local_data->data_out;
    if (!filter_address || !input_address || !output_address ||
        (filter_address & 7) ||
        filter_address + sizeof(local_filter_bytes) < filter_address ||
        local_state->channels != 1 ||
        local_data->input_frames <= 0 || local_data->output_frames <= 0 ||
        (uint64_t)local_data->input_frames > SIZE_MAX / sizeof(float) ||
        (uint64_t)local_data->output_frames > SIZE_MAX / sizeof(float)) {
        goto done;
    }
    input_count = local_data->input_frames;
    output_count = local_data->output_frames;
    input_bytes = input_count * sizeof(float);
    output_bytes = output_count * sizeof(float);
    if (input_bytes > entry->max_input || output_bytes > entry->max_input ||
        input_address + input_bytes < input_address ||
        output_address + output_bytes < output_address) {
        goto done;
    }
    filter = lock_user(VERIFY_WRITE, filter_address,
                       sizeof(local_filter_bytes), 1);
    if (!filter) {
        goto done;
    }
    memcpy(local_filter_bytes, filter, sizeof(local_filter_bytes));
    coeff_address = (uintptr_t)local_filter->coeffs;
    buffer_address = (uintptr_t)local_filter->buffer;
    if (!coeff_address || !buffer_address || (coeff_address & 3) ||
        (buffer_address & 3) || local_filter->coeff_half_len < 1 ||
        local_filter->b_len <= 0 || local_filter->index_inc <= 0 ||
        local_filter->b_current < 0 || local_filter->b_current >= local_filter->b_len ||
        local_filter->b_end < 0 || local_filter->b_end > local_filter->b_len ||
        local_filter->b_real_end < -1 || local_filter->b_real_end > local_filter->b_len) {
        goto done;
    }
    coefficient_count = (size_t)local_filter->coeff_half_len + 2;
    buffer_count = local_filter->b_len;
    if (coefficient_count > SIZE_MAX / sizeof(float) ||
        buffer_count > SIZE_MAX / sizeof(float)) {
        goto done;
    }
    coefficient_bytes = coefficient_count * sizeof(float);
    buffer_bytes = buffer_count * sizeof(float);
    if (coefficient_bytes > entry->max_input || buffer_bytes > entry->max_input ||
        coeff_address + coefficient_bytes < coeff_address ||
        buffer_address + buffer_bytes < buffer_address) {
        goto done;
    }
    if (ranges_overlap(state_address, sizeof(local_state_bytes),
                       filter_address, sizeof(local_filter_bytes)) ||
        ranges_overlap(state_address, sizeof(local_state_bytes), input_address, input_bytes) ||
        ranges_overlap(state_address, sizeof(local_state_bytes), output_address, output_bytes) ||
        ranges_overlap(state_address, sizeof(local_state_bytes), coeff_address, coefficient_bytes) ||
        ranges_overlap(state_address, sizeof(local_state_bytes), buffer_address, buffer_bytes) ||
        ranges_overlap(data_address, sizeof(local_data_bytes),
                       filter_address, sizeof(local_filter_bytes)) ||
        ranges_overlap(data_address, sizeof(local_data_bytes), input_address, input_bytes) ||
        ranges_overlap(data_address, sizeof(local_data_bytes), output_address, output_bytes) ||
        ranges_overlap(data_address, sizeof(local_data_bytes), coeff_address, coefficient_bytes) ||
        ranges_overlap(data_address, sizeof(local_data_bytes), buffer_address, buffer_bytes) ||
        ranges_overlap(filter_address, sizeof(local_filter_bytes), input_address, input_bytes) ||
        ranges_overlap(filter_address, sizeof(local_filter_bytes), output_address, output_bytes) ||
        ranges_overlap(filter_address, sizeof(local_filter_bytes), coeff_address, coefficient_bytes) ||
        ranges_overlap(filter_address, sizeof(local_filter_bytes), buffer_address, buffer_bytes) ||
        ranges_overlap(input_address, input_bytes, output_address, output_bytes) ||
        ranges_overlap(input_address, input_bytes, coeff_address, coefficient_bytes) ||
        ranges_overlap(buffer_address, buffer_bytes, input_address, input_bytes) ||
        ranges_overlap(buffer_address, buffer_bytes, output_address, output_bytes) ||
        ranges_overlap(coeff_address, coefficient_bytes, buffer_address, buffer_bytes) ||
        ranges_overlap(coeff_address, coefficient_bytes, output_address, output_bytes)) {
        goto done;
    }
    input = lock_user(VERIFY_READ, input_address, input_bytes, 0);
    coefficients = lock_user(VERIFY_READ, coeff_address,
                             coefficient_bytes, 0);
    guest_buffer = lock_user(VERIFY_WRITE, buffer_address, buffer_bytes, 1);
    guest_output = lock_user(VERIFY_WRITE, output_address, output_bytes, 1);
    scratch_buffer = g_try_malloc(buffer_bytes);
    scratch_output = g_try_malloc0(output_bytes);
    if (!input || !coefficients || !guest_buffer || !guest_output ||
        !scratch_buffer || !scratch_output) {
        goto done;
    }
    memcpy(scratch_buffer, guest_buffer, buffer_bytes);
    if (!fp_double_domain_ok(local_state->last_ratio) ||
        !fp_double_domain_ok(local_state->last_position) ||
        !fp_double_domain_ok(local_data->src_ratio) ||
        !fp_float_domain_ok(input, input_count) ||
        !fp_float_domain_ok(coefficients, coefficient_count) ||
        !fp_float_domain_ok(scratch_buffer, buffer_count)) {
        goto done;
    }
    if (fegetenv(&saved_fenv) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0) {
        goto done;
    }
    variant_ok = llmopt_variant_fp_samplerate(
        entry->variant, local_state_bytes, local_data_bytes,
        local_filter_bytes, coefficients, coefficient_count,
        scratch_buffer, buffer_count, input, input_count,
        scratch_output, output_count);
    host_exceptions = fetestexcept(FE_ALL_EXCEPT);
    fesetenv(&saved_fenv);
    if (!variant_ok ||
        (host_exceptions & (FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW)) ||
        local_filter->out_gen < 0 || (uint64_t)local_filter->out_gen > output_count ||
        !fp_double_domain_ok(local_state->last_ratio) ||
        !fp_double_domain_ok(local_state->last_position) ||
        !fp_float_domain_ok(scratch_buffer, buffer_count) ||
        !fp_float_domain_ok(scratch_output, local_filter->out_gen)) {
        goto done;
    }
    committed_output_bytes = local_filter->out_gen * sizeof(float);
    local_state->private_data = (void *)(uintptr_t)filter_address;
    local_data->data_in = (const float *)(uintptr_t)input_address;
    local_data->data_out = (float *)(uintptr_t)output_address;
    local_filter->coeffs = (const float *)(uintptr_t)coeff_address;
    local_filter->buffer = (float *)(uintptr_t)buffer_address;
    memcpy(state, local_state_bytes, sizeof(local_state_bytes));
    memcpy(data, local_data_bytes, sizeof(local_data_bytes));
    memcpy(filter, local_filter_bytes, sizeof(local_filter_bytes));
    memcpy(guest_buffer, scratch_buffer, buffer_bytes);
    memcpy(guest_output, scratch_output, committed_output_bytes);
    if (host_exceptions & FE_INEXACT) {
        vfp_set_fpsr(env, vfp_get_fpsr(env) | (1u << 4));
    }
    env->xregs[0] = 0;
    env->pc = env->xregs[30];
    success = true;

done:
    if (input) {
        unlock_user(input, input_address, 0);
    }
    if (coefficients) {
        unlock_user(coefficients, coeff_address, 0);
    }
    if (guest_buffer) {
        unlock_user(guest_buffer, buffer_address,
                    success ? buffer_bytes : 0);
    }
    if (guest_output) {
        unlock_user(guest_output, output_address,
                    success ? committed_output_bytes : 0);
    }
    if (filter) {
        unlock_user(filter, filter_address,
                    success ? sizeof(local_filter_bytes) : 0);
    }
    if (data) {
        unlock_user(data, data_address,
                    success ? sizeof(local_data_bytes) : 0);
    }
    if (state) {
        unlock_user(state, state_address,
                    success ? sizeof(local_state_bytes) : 0);
    }
    return success;
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

static void begin_baseline_region(CPUARMState *env, uint64_t start_ns)
{
    runtime.baseline_region_active = true;
    runtime.baseline_return_pc = env->xregs[30];
    runtime.baseline_start_ns = start_ns;
}

static bool unprotected_probe_changed(CPUState *cpu, CPUARMState *env)
{
    uint64_t address = env->xregs[3];
    uint64_t before, after;
    uint64_t *probe;

    if (!runtime.test_unprotected_probe_ms) {
        return false;
    }
    if (!runtime.test_probe_counter) {
        bool overlap = observe_other_cpu_running(
            cpu, runtime.test_unprotected_probe_ms);
        if (overlap) {
            runtime.negative_control_overlaps++;
        }
        return overlap;
    }
    probe = lock_user(VERIFY_READ, address, sizeof(*probe), 1);
    if (!probe) {
        return false;
    }
    before = qatomic_read(probe);
    g_usleep(runtime.test_unprotected_probe_ms * 1000);
    after = qatomic_read(probe);
    unlock_user(probe, address, 0);
    if (before != after) {
        runtime.negative_control_overlaps++;
    }
    return before != after;
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
    LlmoptIdentityState identity_state;

    if (!runtime.initialized || !runtime.enabled) {
        return LLMOPT_NOT_APPLICABLE;
    }
    if (runtime.baseline_region_active && pc == runtime.baseline_return_pc) {
        runtime.baseline_region_ns += now_ns() - runtime.baseline_start_ns;
        runtime.baseline_region_count++;
        runtime.baseline_region_active = false;
    }
    if (runtime.sequence_region_active && pc == runtime.sequence_return_pc) {
        runtime.sequence_region_ns += now_ns() - runtime.sequence_start_ns;
        runtime.sequence_region_count++;
        runtime.sequence_region_active = false;
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
    /* A repeated block entry proves that the preceding call returned. */
    if (runtime.baseline_region_active) {
        runtime.baseline_region_ns += now_ns() - runtime.baseline_start_ns;
        runtime.baseline_region_count++;
        runtime.baseline_region_active = false;
    }
    if (runtime.sequence_region_active) {
        runtime.sequence_region_ns += now_ns() - runtime.sequence_start_ns;
        runtime.sequence_region_count++;
        runtime.sequence_region_active = false;
    }
    entry_start = now_ns();
    runtime.attempts++;
    runtime.guard_checks++;
    env = cpu_env(cpu);
    task = get_task_state(cpu);
    identity_state = guest_identity_activation_state();
    if (identity_state == LLMOPT_IDENTITY_PENDING) {
        runtime.identity_pending_fallbacks++;
        begin_baseline_region(env, entry_start);
        return guarded_fallback(pc, "guest_binary_identity_pending");
    }
    if (identity_state != LLMOPT_IDENTITY_MATCHED) {
        LlmoptDispatchResult result =
            guarded_fallback(pc, "guest_binary_identity_mismatch");

        runtime.identity_mismatch_fallbacks++;
        begin_baseline_region(env, entry_start);
        disable_map("guest binary identity rejected by background hash");
        return result;
    }
    if (runtime.pending_recheck && runtime.fallback_pc == pc) {
        runtime.rechecks_after_fallback++;
        runtime.pending_recheck = false;
        if (runtime.trace) {
            fprintf(stderr, "LLMOPT_RECHECK pc=0x%" PRIx64 " count=%" PRIu64 "\n",
                    (uint64_t)pc, runtime.rechecks_after_fallback);
        }
    }
    forced_code_change_now = entry->invocation_mode ==
        LLMOPT_INVOKE_EXCLUSIVE_SECTION ? false : force_code_change(cpu, entry);
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
    if (entry->invocation_mode == LLMOPT_INVOKE_EXCLUSIVE_SECTION) {
        if (env->xregs[30] != entry->runtime_return_pc) {
            runtime.caller_pc_rejects++;
            return guarded_fallback(pc, "exclusive_caller_pc");
        }
        if (runtime.debugger_active || cpu->singlestep_enabled ||
            !QTAILQ_EMPTY(&cpu->watchpoints) ||
            qatomic_read(&task->signal_pending) ||
            qatomic_read(&cpu->exit_request)) {
            runtime.state_rejects++;
            return guarded_fallback(pc, "exclusive_preflight_state");
        }
        if (runtime.test_unprotected_probe_ms) {
            unprotected_probe_changed(cpu, env);
            return guarded_fallback(pc, "unprotected_negative_control");
        }
        if (runtime.baseline_only) {
            begin_baseline_region(env, entry_start);
            return guarded_fallback(pc, "baseline_measurement");
        }
        exclusive_pending_entry = entry;
        exclusive_pending_start_ns = entry_start;
        runtime.exclusive_requests++;
        return LLMOPT_EXCLUSIVE_REQUEST;
    }
    bool one_guest_cpu = single_guest_cpu();
    if (runtime.debugger_active || cpu->singlestep_enabled ||
        !QTAILQ_EMPTY(&cpu->watchpoints) ||
        qatomic_read(&task->signal_pending) ||
        qatomic_read(&cpu->exit_request) || !one_guest_cpu) {
        if (runtime.trace) {
            fprintf(stderr, "LLMOPT_RUNTIME_STATE debugger=%u singlestep=%u "
                    "watchpoints=%u signal_pending=%u exit_request=%u single_guest_cpu=%u\n",
                    runtime.debugger_active, cpu->singlestep_enabled,
                    !QTAILQ_EMPTY(&cpu->watchpoints),
                    qatomic_read(&task->signal_pending),
                    qatomic_read(&cpu->exit_request), one_guest_cpu);
        }
        runtime.state_rejects++;
        if (!one_guest_cpu) {
            runtime.single_cpu_guard_rejects++;
        }
        return guarded_fallback(pc, "runtime_state");
    }
    if (runtime.force_guard_fail_once && !runtime.forced_guard_fired) {
        runtime.forced_guard_fired = true;
        runtime.forced_rejects++;
        return guarded_fallback(pc, "forced_test_guard");
    }
    if (runtime.baseline_only) {
        begin_baseline_region(env, entry_start);
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
    } else if (entry->algorithm == LLMOPT_ALGO_MEMCPY) {
        substituted = substitute_memcpy(env, entry);
    } else if (entry->algorithm == LLMOPT_ALGO_LZ_MATCH_COPY) {
        substituted = substitute_lz_match_copy(env, entry);
    } else if (entry->algorithm == LLMOPT_ALGO_MEMSET) {
        substituted = substitute_memset(env, entry);
    } else if (entry->algorithm == LLMOPT_ALGO_XXH64_STREAM) {
        substituted = substitute_xxh64_stream(env, entry);
    } else if (entry->algorithm == LLMOPT_ALGO_SHA256_STREAM) {
        substituted = substitute_sha256_stream(env, entry);
    } else if (entry->algorithm == LLMOPT_ALGO_FP_SAMPLERATE) {
        substituted = substitute_fp_samplerate(env, entry);
    } else {
        substituted = substitute_scalar(env, entry);
    }
    if (!substituted) {
        runtime.memory_rejects++;
        return guarded_fallback(pc, "operand_or_memory");
    }
    runtime.substitution_region_ns += now_ns() - entry_start;
    runtime.substitution_region_count++;
    if (runtime.report_enabled) {
        runtime.sequence_region_active = true;
        runtime.sequence_return_pc = env->xregs[30];
        runtime.sequence_start_ns = entry_start;
    }
    if (!guards_passed) {
        runtime.unguarded_executions++;
        return guarded_fallback(pc, "internal_guard_audit");
    }
    runtime.hits++;
    if (entry->variant == LLMOPT_VARIANT_PORTABLE_C) {
        runtime.portable_variant_hits++;
    } else if (entry->variant == LLMOPT_VARIANT_BULK_C) {
        runtime.bulk_variant_hits++;
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
                    "portable_c" :
                entry->variant == LLMOPT_VARIANT_BULK_C ?
                    "bulk_c" : "x86_64_optimized",
                runtime.hits);
    }
    return LLMOPT_SUBSTITUTED;
}

static bool another_guest_cpu_running(CPUState *cpu)
{
    CPUState *candidate;
    bool running = false;

    cpu_list_lock();
    CPU_FOREACH(candidate) {
        if (candidate != cpu && candidate->running) {
            running = true;
            break;
        }
    }
    cpu_list_unlock();
    return running;
}

LlmoptDispatchResult llmopt_run_pending_exclusive(CPUState *cpu)
{
    LlmoptEntry *entry = exclusive_pending_entry;
    CPUARMState *env = cpu_env(cpu);
    TaskState *task = get_task_state(cpu);
    uint64_t start_ns = exclusive_pending_start_ns;
    uint64_t wait_start, acquired_ns, released_ns;
    const char *fallback_reason = NULL;
    bool substituted = false;
    bool forced_change;
    uint64_t probe_before = 0, probe_after = 0;
    uint64_t probe_address = 0;
    uint64_t *probe = NULL;

    exclusive_pending_entry = NULL;
    exclusive_pending_start_ns = 0;
    if (!entry) {
        return LLMOPT_NOT_APPLICABLE;
    }
    if (entry->invocation_mode != LLMOPT_INVOKE_EXCLUSIVE_SECTION) {
        runtime.invocation_mode_refusals++;
        return LLMOPT_NOT_APPLICABLE;
    }
    if (another_guest_cpu_running(cpu)) {
        runtime.exclusive_contentions++;
    }
    wait_start = now_ns();
    start_exclusive();
    acquired_ns = now_ns();
    runtime.exclusive_entries++;
    runtime.exclusive_wait_events++;
    runtime.exclusive_wait_ns += acquired_ns - wait_start;
    runtime.exclusive_max_wait_ns = MAX(runtime.exclusive_max_wait_ns,
                                        acquired_ns - wait_start);

    if (guest_identity_activation_state() != LLMOPT_IDENTITY_MATCHED) {
        fallback_reason = "exclusive_identity_recheck";
    } else if (env->pc != entry->runtime_pc) {
        fallback_reason = "exclusive_entry_pc_recheck";
    } else if (env->xregs[30] != entry->runtime_return_pc) {
        runtime.caller_pc_rejects++;
        fallback_reason = "exclusive_caller_pc_recheck";
    } else if (runtime.debugger_active || cpu->singlestep_enabled ||
               !QTAILQ_EMPTY(&cpu->watchpoints) ||
               qatomic_read(&task->signal_pending) ||
               qatomic_read(&cpu->exit_request)) {
        runtime.state_rejects++;
        fallback_reason = "exclusive_runtime_state_recheck";
    }

    forced_change = fallback_reason ? false : force_code_change(cpu, entry);
    if (!fallback_reason) {
        runtime.page_version_checks++;
        if (!entry->code_verified ||
            !llmopt_page_versions_match(entry->page_tokens,
                                        entry->page_token_count)) {
            bool restored = restore_forced_code_change(cpu);

            entry->code_verified = false;
            runtime.late_page_version_rejects++;
            if (restored && forced_change) {
                entry_bytes_reverify(entry);
            }
            fallback_reason = "exclusive_code_page_recheck";
        } else if (forced_change) {
            runtime.page_write_detection_failures++;
            entry->code_verified = false;
            restore_forced_code_change(cpu);
            fallback_reason = "exclusive_forced_write_undetected";
        }
    }
    if (!fallback_reason && runtime.force_guard_fail_once &&
        !runtime.forced_guard_fired) {
        runtime.forced_guard_fired = true;
        runtime.forced_rejects++;
        fallback_reason = "exclusive_forced_test_guard";
    }
    if (!fallback_reason) {
        mmap_lock();
        runtime.page_version_checks++;
        if (!entry->code_verified ||
            !llmopt_page_versions_match(entry->page_tokens,
                                        entry->page_token_count) ||
            env->pc != entry->runtime_pc ||
            env->xregs[30] != entry->runtime_return_pc ||
            qatomic_read(&task->signal_pending) ||
            qatomic_read(&cpu->exit_request)) {
            fallback_reason = "exclusive_final_authority_recheck";
        } else {
            if (runtime.test_probe_counter) {
                probe_address = env->xregs[3];
                probe = lock_user(VERIFY_READ, probe_address,
                                  sizeof(*probe), 1);
                if (!probe) {
                    fallback_reason = "exclusive_probe_memory";
                } else {
                    probe_before = qatomic_read(probe);
                }
            }
            if (!fallback_reason && runtime.test_exclusive_hold_ms &&
                observe_other_cpu_running(cpu,
                                          runtime.test_exclusive_hold_ms)) {
                runtime.exclusive_overlap_failures++;
                fallback_reason = "exclusive_guest_cpu_overlap";
            }
            if (!fallback_reason && probe) {
                probe_after = qatomic_read(probe);
                if (probe_before != probe_after) {
                    runtime.exclusive_overlap_failures++;
                    fallback_reason = "exclusive_guest_overlap";
                }
            }
            if (!fallback_reason &&
                entry->algorithm == LLMOPT_ALGO_XXH64_STREAM) {
                substituted = substitute_xxh64_stream(env, entry);
                if (!substituted) {
                    runtime.memory_rejects++;
                    fallback_reason = "exclusive_operand_or_memory";
                }
            } else if (!fallback_reason) {
                runtime.invocation_mode_refusals++;
                fallback_reason = "exclusive_unsupported_adapter";
            }
            if (probe) {
                unlock_user(probe, probe_address, 0);
            }
        }
        mmap_unlock();
    }

    released_ns = now_ns();
    end_exclusive();
    runtime.exclusive_exits++;
    runtime.exclusive_hold_ns += released_ns - acquired_ns;
    runtime.exclusive_max_hold_ns = MAX(runtime.exclusive_max_hold_ns,
                                        released_ns - acquired_ns);
    if (fallback_reason) {
        runtime.exclusive_recheck_fallbacks++;
        begin_baseline_region(env, start_ns);
        return guarded_fallback(entry->runtime_pc, fallback_reason);
    }

    runtime.substitution_region_ns += released_ns - start_ns;
    runtime.substitution_region_count++;
    if (runtime.report_enabled) {
        runtime.sequence_region_active = true;
        runtime.sequence_return_pc = env->xregs[30];
        runtime.sequence_start_ns = start_ns;
    }
    runtime.hits++;
    if (entry->variant == LLMOPT_VARIANT_PORTABLE_C) {
        runtime.portable_variant_hits++;
    } else if (entry->variant == LLMOPT_VARIANT_BULK_C) {
        runtime.bulk_variant_hits++;
    } else {
        runtime.optimized_variant_hits++;
    }
    if (entry->stable_direct) {
        runtime.stable_direct_hits++;
    }
    if (runtime.trace) {
        fprintf(stderr,
                "LLMOPT_EXCLUSIVE_HIT pc=0x%" PRIx64
                " caller=0x%" PRIx64 " hit=%" PRIu64 "\n",
                entry->runtime_pc, entry->runtime_return_pc, runtime.hits);
    }
    return LLMOPT_SUBSTITUTED;
}

#endif /* TARGET_AARCH64 */

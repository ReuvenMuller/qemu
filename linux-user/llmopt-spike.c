/*
 * Movement 2 Goal 1: evidence-only AArch64 linux-user dispatch spike.
 *
 * This is intentionally a narrow hand-installed substitution.  It is not the
 * final catalog/runtime.  The entry PC, exact function-byte fingerprint, ABI,
 * and maximum input length are supplied by a pre-validated offline verdict.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "exec/cpu-common.h"
#include "qemu.h"
#include "user-internals.h"

bool llmopt_spike_try_dispatch(CPUState *cpu, vaddr pc);

#ifndef TARGET_AARCH64

bool llmopt_spike_try_dispatch(CPUState *cpu, vaddr pc)
{
    return false;
}

#else

#define XXH_P1 UINT64_C(11400714785074694791)
#define XXH_P2 UINT64_C(14029467366897019727)
#define XXH_P3 UINT64_C(1609587929392839161)
#define XXH_P4 UINT64_C(9650029242287828579)
#define XXH_P5 UINT64_C(2870177450012600261)

typedef struct LlmoptSpikeState {
    bool initialized;
    bool enabled;
    bool installed;
    bool trace;
    bool copy_mode;
    uint64_t entry;
    uint64_t code_hash;
    size_t code_size;
    size_t max_len;
    uint64_t init_ns;
    uint64_t install_ns;
    uint64_t attempts;
    uint64_t hits;
    uint64_t code_rejects;
    uint64_t memory_rejects;
    uint64_t state_rejects;
    uint64_t copied_bytes;
    uint64_t copy_ns;
    uint64_t digest_ns;
} LlmoptSpikeState;

static LlmoptSpikeState spike;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static uint64_t parse_u64(const char *name, bool *ok)
{
    const char *s = getenv(name);
    char *end = NULL;
    unsigned long long value;
    if (!s || !*s) {
        *ok = false;
        return 0;
    }
    errno = 0;
    value = strtoull(s, &end, 0);
    if (errno || !end || *end) {
        *ok = false;
        return 0;
    }
    return value;
}

static void report(void)
{
    if (!spike.enabled) {
        return;
    }
    fprintf(stderr,
            "LLMOPT_SPIKE init_ns=%" PRIu64 " install_ns=%" PRIu64
            " attempts=%" PRIu64 " hits=%" PRIu64
            " code_rejects=%" PRIu64 " memory_rejects=%" PRIu64
            " state_rejects=%" PRIu64 " copied_bytes=%" PRIu64
            " copy_ns=%" PRIu64 " digest_ns=%" PRIu64
            " code_cache_flushes=0 tb_patches=0\n",
            spike.init_ns, spike.install_ns, spike.attempts, spike.hits,
            spike.code_rejects, spike.memory_rejects, spike.state_rejects,
            spike.copied_bytes, spike.copy_ns, spike.digest_ns);
}

static void initialize(void)
{
    uint64_t start = now_ns();
    bool ok = true;
    const char *enable = getenv("QEMU_LLMOPT_XXH64");
    spike.initialized = true;
    if (!enable || strcmp(enable, "1") != 0) {
        spike.init_ns = now_ns() - start;
        return;
    }
    spike.entry = parse_u64("QEMU_LLMOPT_XXH64_ENTRY", &ok);
    spike.code_hash = parse_u64("QEMU_LLMOPT_XXH64_CODE_HASH", &ok);
    spike.code_size = parse_u64("QEMU_LLMOPT_XXH64_CODE_SIZE", &ok);
    spike.max_len = parse_u64("QEMU_LLMOPT_XXH64_MAX_LEN", &ok);
    if (!ok || !spike.entry || !spike.code_size || !spike.max_len) {
        fprintf(stderr, "LLMOPT_SPIKE disabled: invalid verdict environment\n");
        spike.init_ns = now_ns() - start;
        return;
    }
    spike.enabled = true;
    spike.trace = g_strcmp0(getenv("QEMU_LLMOPT_XXH64_TRACE"), "1") == 0;
    spike.copy_mode = g_strcmp0(getenv("QEMU_LLMOPT_XXH64_COPY"), "1") == 0;
    atexit(report);
    spike.init_ns = now_ns() - start;
}

static inline uint64_t rotl64(uint64_t x, unsigned r)
{
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t read64le(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return le64_to_cpu(v);
}

static inline uint32_t read32le(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return le32_to_cpu(v);
}

static inline uint64_t xxh_round(uint64_t acc, uint64_t input)
{
    acc += input * XXH_P2;
    acc = rotl64(acc, 31);
    return acc * XXH_P1;
}

static inline uint64_t xxh_merge(uint64_t acc, uint64_t lane)
{
    lane = xxh_round(0, lane);
    acc ^= lane;
    return acc * XXH_P1 + XXH_P4;
}

static uint64_t host_xxh64(const uint8_t *p, size_t len, uint64_t seed)
{
    const uint8_t *end = p + len;
    uint64_t h;
    if (len >= 32) {
        const uint8_t *limit = end - 32;
        uint64_t v1 = seed + XXH_P1 + XXH_P2;
        uint64_t v2 = seed + XXH_P2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_P1;
        do {
            v1 = xxh_round(v1, read64le(p)); p += 8;
            v2 = xxh_round(v2, read64le(p)); p += 8;
            v3 = xxh_round(v3, read64le(p)); p += 8;
            v4 = xxh_round(v4, read64le(p)); p += 8;
        } while (p <= limit);
        h = rotl64(v1, 1) + rotl64(v2, 7) +
            rotl64(v3, 12) + rotl64(v4, 18);
        h = xxh_merge(h, v1);
        h = xxh_merge(h, v2);
        h = xxh_merge(h, v3);
        h = xxh_merge(h, v4);
    } else {
        h = seed + XXH_P5;
    }
    h += len;
    while (p + 8 <= end) {
        uint64_t k = xxh_round(0, read64le(p));
        h ^= k;
        h = rotl64(h, 27) * XXH_P1 + XXH_P4;
        p += 8;
    }
    if (p + 4 <= end) {
        h ^= (uint64_t)read32le(p) * XXH_P1;
        h = rotl64(h, 23) * XXH_P2 + XXH_P3;
        p += 4;
    }
    while (p < end) {
        h ^= (uint64_t)*p++ * XXH_P5;
        h = rotl64(h, 11) * XXH_P1;
    }
    h ^= h >> 33;
    h *= XXH_P2;
    h ^= h >> 29;
    h *= XXH_P3;
    h ^= h >> 32;
    return h;
}

static uint64_t fnv1a64(const uint8_t *p, size_t len)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
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

bool llmopt_spike_try_dispatch(CPUState *cpu, vaddr pc)
{
    CPUARMState *env;
    TaskState *ts;
    uint8_t *code = NULL;
    uint8_t *input = NULL;
    uint64_t start, input_addr, len, seed, result;
    uint64_t copy_elapsed, digest_elapsed;

    if (unlikely(!spike.initialized)) {
        initialize();
    }
    if (likely(!spike.enabled || pc != spike.entry)) {
        return false;
    }
    spike.attempts++;
    env = cpu_env(cpu);
    ts = get_task_state(cpu);

    /* Preserve debugger and signal semantics by refusing the fast path. */
    if (cpu->singlestep_enabled || !QTAILQ_EMPTY(&cpu->watchpoints) ||
        qatomic_read(&ts->signal_pending) ||
        qatomic_read(&cpu->exit_request) || !single_guest_cpu()) {
        spike.state_rejects++;
        if (spike.trace) {
            fprintf(stderr, "LLMOPT_REJECT reason=state pc=0x%" PRIx64 "\n",
                    (uint64_t)pc);
        }
        return false;
    }

    start = now_ns();
    code = g_try_malloc(spike.code_size);
    if (!code || copy_from_user(code, pc, spike.code_size) != 0 ||
        fnv1a64(code, spike.code_size) != spike.code_hash) {
        g_free(code);
        spike.code_rejects++;
        if (spike.trace) {
            fprintf(stderr, "LLMOPT_REJECT reason=code pc=0x%" PRIx64 "\n",
                    (uint64_t)pc);
        }
        return false;
    }
    g_free(code);
    if (!spike.installed) {
        spike.install_ns = now_ns() - start;
        spike.installed = true;
    }

    input_addr = env->xregs[0];
    len = env->xregs[1];
    seed = env->xregs[2];
    if (len > spike.max_len || input_addr + len < input_addr ||
        len > SIZE_MAX) {
        spike.memory_rejects++;
        if (spike.trace) {
            fprintf(stderr, "LLMOPT_REJECT reason=length len=%" PRIu64 "\n",
                    len);
        }
        return false;
    }

    start = now_ns();
    if (spike.copy_mode) {
        input = g_try_malloc(len ? len : 1);
        if (!input || (len && copy_from_user(input, input_addr, len) != 0)) {
            g_free(input);
            spike.memory_rejects++;
            if (spike.trace) {
                fprintf(stderr,
                        "LLMOPT_REJECT reason=memory len=%" PRIu64 "\n", len);
            }
            return false;
        }
    } else {
        input = lock_user(VERIFY_READ, input_addr, len, 1);
        if (!input) {
            spike.memory_rejects++;
            if (spike.trace) {
                fprintf(stderr,
                        "LLMOPT_REJECT reason=memory len=%" PRIu64 "\n", len);
            }
            return false;
        }
    }
    copy_elapsed = now_ns() - start;
    spike.copy_ns += copy_elapsed;
    spike.copied_bytes += len;

    start = now_ns();
    result = host_xxh64(input, len, seed);
    digest_elapsed = now_ns() - start;
    spike.digest_ns += digest_elapsed;
    if (spike.copy_mode) {
        g_free(input);
    } else {
        unlock_user(input, input_addr, 0);
    }

    env->xregs[0] = result;
    env->pc = env->xregs[30];
    spike.hits++;
    if (spike.trace) {
        fprintf(stderr,
                "LLMOPT_HIT hit=%" PRIu64 " len=%" PRIu64
                " install_ns=%" PRIu64 " copy_ns=%" PRIu64
                " digest_ns=%" PRIu64 " input_mode=%s"
                " code_cache_flushes=0 tb_patches=0\n",
                spike.hits, len, spike.install_ns, copy_elapsed, digest_elapsed,
                spike.copy_mode ? "copy" : "direct");
    }
    return true;
}

#endif /* TARGET_AARCH64 */

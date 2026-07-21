/* Fail-closed dispatch-entry substitution hook for linux-user. */
#ifndef EXEC_LLMOPT_H
#define EXEC_LLMOPT_H

#include "exec/cpu-common.h"

typedef enum LlmoptDispatchResult {
    LLMOPT_NOT_APPLICABLE = 0,
    LLMOPT_SUBSTITUTED,
    LLMOPT_GUARDED_FALLBACK,
    LLMOPT_EXCLUSIVE_REQUEST,
} LlmoptDispatchResult;

void llmopt_initialize(bool debugger_active, const char *guest_binary,
                       uint64_t guest_load_bias);
void llmopt_cleanup(void);
void llmopt_report(void);
LlmoptDispatchResult llmopt_try_dispatch(CPUState *cpu, vaddr pc);
LlmoptDispatchResult llmopt_run_pending_exclusive(CPUState *cpu);

#endif

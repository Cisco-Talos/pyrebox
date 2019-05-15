#ifndef S390X_TARGET_SIGNAL_H
#define S390X_TARGET_SIGNAL_H

typedef struct target_sigaltstack {
    abi_ulong ss_sp;
    int ss_flags;
    abi_ulong ss_size;
} target_stack_t;

/*
 * sigaltstack controls
 */
#define TARGET_SS_ONSTACK      1
#define TARGET_SS_DISABLE      2

#define TARGET_MINSIGSTKSZ     2048
#define TARGET_SIGSTKSZ        8192

#include "../generic/signal.h"

#define TARGET_ARCH_HAS_SETUP_FRAME
#endif /* S390X_TARGET_SIGNAL_H */

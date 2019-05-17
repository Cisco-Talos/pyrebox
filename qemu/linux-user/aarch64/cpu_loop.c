/*
 *  qemu user cpu loop
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "cpu_loop-common.h"

#define get_user_code_u32(x, gaddr, env)                \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && bswap_code(arm_sctlr_b(env))) {     \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_code_u16(x, gaddr, env)                \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && bswap_code(arm_sctlr_b(env))) {     \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_data_u32(x, gaddr, env)                \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && arm_cpu_bswap_data(env)) {          \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_data_u16(x, gaddr, env)                \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && arm_cpu_bswap_data(env)) {          \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

#define put_user_data_u32(x, gaddr, env)                \
    ({ typeof(x) __x = (x);                             \
        if (arm_cpu_bswap_data(env)) {                  \
            __x = bswap32(__x);                         \
        }                                               \
        put_user_u32(__x, (gaddr));                     \
    })

#define put_user_data_u16(x, gaddr, env)                \
    ({ typeof(x) __x = (x);                             \
        if (arm_cpu_bswap_data(env)) {                  \
            __x = bswap16(__x);                         \
        }                                               \
        put_user_u16(__x, (gaddr));                     \
    })

/* AArch64 main loop */
void cpu_loop(CPUARMState *env)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int trapnr;
    abi_long ret;
    target_siginfo_t info;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case EXCP_SWI:
            ret = do_syscall(env,
                             env->xregs[8],
                             env->xregs[0],
                             env->xregs[1],
                             env->xregs[2],
                             env->xregs[3],
                             env->xregs[4],
                             env->xregs[5],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->xregs[0] = ret;
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_UDEF:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->pc;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_PREFETCH_ABORT:
        case EXCP_DATA_ABORT:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            /* XXX: check env->error_code */
            info.si_code = TARGET_SEGV_MAPERR;
            info._sifields._sigfault._addr = env->exception.vaddress;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_DEBUG:
        case EXCP_BKPT:
            info.si_signo = TARGET_SIGTRAP;
            info.si_errno = 0;
            info.si_code = TARGET_TRAP_BRKPT;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_SEMIHOST:
            env->xregs[0] = do_arm_semihosting(env);
            break;
        case EXCP_YIELD:
            /* nothing to do here for user-mode, just resume guest code */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n", trapnr);
            abort();
        }
        process_pending_signals(env);
        /* Exception return on AArch64 always clears the exclusive monitor,
         * so any return to running guest code implies this.
         */
        env->exclusive_addr = -1;
    }
}

static uint64_t arm_rand64(void)
{
    int shift = 64 - clz64(RAND_MAX);
    int i, n = 64 / shift + (64 % shift != 0);
    uint64_t ret = 0;

    for (i = 0; i < n; i++) {
        ret = (ret << shift) | rand();
    }
    return ret;
}

void arm_init_pauth_key(ARMPACKey *key)
{
    key->lo = arm_rand64();
    key->hi = arm_rand64();
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    TaskState *ts = cs->opaque;
    struct image_info *info = ts->info;
    int i;

    if (!(arm_feature(env, ARM_FEATURE_AARCH64))) {
        fprintf(stderr,
                "The selected ARM CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < 31; i++) {
        env->xregs[i] = regs->regs[i];
    }
    env->pc = regs->pc;
    env->xregs[31] = regs->sp;
#ifdef TARGET_WORDS_BIGENDIAN
    env->cp15.sctlr_el[1] |= SCTLR_E0E;
    for (i = 1; i < 4; ++i) {
        env->cp15.sctlr_el[i] |= SCTLR_EE;
    }
#endif

    if (cpu_isar_feature(aa64_pauth, cpu)) {
        arm_init_pauth_key(&env->apia_key);
        arm_init_pauth_key(&env->apib_key);
        arm_init_pauth_key(&env->apda_key);
        arm_init_pauth_key(&env->apdb_key);
        arm_init_pauth_key(&env->apga_key);
    }

    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
}

/*
 *  x86 memory access helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "qemu/int128.h"
#include "qemu/atomic128.h"
#include "tcg.h"

void helper_cmpxchg8b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

    oldv = cpu_ldq_data_ra(env, a0, ra);
    newv = (cmpv == oldv ? newv : oldv);
    /* always do the store */
    cpu_stq_data_ra(env, a0, newv, ra);

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg8b(CPUX86State *env, target_ulong a0)
{
#ifdef CONFIG_ATOMIC64
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

#ifdef CONFIG_USER_ONLY
    {
        uint64_t *haddr = g2h(a0);
        cmpv = cpu_to_le64(cmpv);
        newv = cpu_to_le64(newv);
        oldv = atomic_cmpxchg__nocheck(haddr, cmpv, newv);
        oldv = le64_to_cpu(oldv);
    }
#else
    {
        uintptr_t ra = GETPC();
        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ, mem_idx);
        oldv = helper_atomic_cmpxchgq_le_mmu(env, a0, cmpv, newv, oi, ra);
    }
#endif

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
#else
    cpu_loop_exit_atomic(ENV_GET_CPU(env), GETPC());
#endif /* CONFIG_ATOMIC64 */
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    Int128 oldv, cmpv, newv;
    uint64_t o0, o1;
    int eflags;
    bool success;

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
    newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

    o0 = cpu_ldq_data_ra(env, a0 + 0, ra);
    o1 = cpu_ldq_data_ra(env, a0 + 8, ra);

    oldv = int128_make128(o0, o1);
    success = int128_eq(oldv, cmpv);
    if (!success) {
        newv = oldv;
    }

    cpu_stq_data_ra(env, a0 + 0, int128_getlo(newv), ra);
    cpu_stq_data_ra(env, a0 + 8, int128_gethi(newv), ra);

    if (success) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = int128_getlo(oldv);
        env->regs[R_EDX] = int128_gethi(oldv);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg16b(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    } else if (HAVE_CMPXCHG128) {
        int eflags = cpu_cc_compute_all(env, CC_OP);

        Int128 cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
        Int128 newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ | MO_ALIGN_16, mem_idx);
        Int128 oldv = helper_atomic_cmpxchgo_le_mmu(env, a0, cmpv,
                                                    newv, oi, ra);

        if (int128_eq(oldv, cmpv)) {
            eflags |= CC_Z;
        } else {
            env->regs[R_EAX] = int128_getlo(oldv);
            env->regs[R_EDX] = int128_gethi(oldv);
            eflags &= ~CC_Z;
        }
        CC_SRC = eflags;
    } else {
        cpu_loop_exit_atomic(ENV_GET_CPU(env), ra);
    }
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data_ra(env, a0, GETPC());
    high = cpu_ldsw_data_ra(env, a0 + 2, GETPC());
    v = (int16_t)v;
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data_ra(env, a0, GETPC());
    high = cpu_ldl_data_ra(env, a0 + 4, GETPC());
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

#if !defined(CONFIG_USER_ONLY)
/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *cs, target_ulong addr, int size,
              MMUAccessType access_type, int mmu_idx, uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int ret;

    env->retaddr = retaddr;
    ret = x86_cpu_handle_mmu_fault(cs, addr, size, access_type, mmu_idx);
    if (ret) {
        raise_exception_err_ra(env, cs->exception_index, env->error_code, retaddr);
    }
}
#endif

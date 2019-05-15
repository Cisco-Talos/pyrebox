/*
 *  ARM helper routines
 *
 *  Copyright (c) 2005-2007 CodeSourcery, LLC
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
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "internals.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"

#define SIGNBIT (uint32_t)0x80000000
#define SIGNBIT64 ((uint64_t)1 << 63)

static CPUState *do_raise_exception(CPUARMState *env, uint32_t excp,
                                    uint32_t syndrome, uint32_t target_el)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));

    if (target_el == 1 && (arm_hcr_el2_eff(env) & HCR_TGE)) {
        /*
         * Redirect NS EL1 exceptions to NS EL2. These are reported with
         * their original syndrome register value, with the exception of
         * SIMD/FP access traps, which are reported as uncategorized
         * (see DDI0478C.a D1.10.4)
         */
        target_el = 2;
        if (syn_get_ec(syndrome) == EC_ADVSIMDFPACCESSTRAP) {
            syndrome = syn_uncategorized();
        }
    }

    assert(!excp_is_internal(excp));
    cs->exception_index = excp;
    env->exception.syndrome = syndrome;
    env->exception.target_el = target_el;

    return cs;
}

void raise_exception(CPUARMState *env, uint32_t excp,
                     uint32_t syndrome, uint32_t target_el)
{
    CPUState *cs = do_raise_exception(env, excp, syndrome, target_el);
    cpu_loop_exit(cs);
}

void raise_exception_ra(CPUARMState *env, uint32_t excp, uint32_t syndrome,
                        uint32_t target_el, uintptr_t ra)
{
    CPUState *cs = do_raise_exception(env, excp, syndrome, target_el);
    cpu_loop_exit_restore(cs, ra);
}

uint32_t HELPER(neon_tbl)(uint32_t ireg, uint32_t def, void *vn,
                          uint32_t maxindex)
{
    uint32_t val, shift;
    uint64_t *table = vn;

    val = 0;
    for (shift = 0; shift < 32; shift += 8) {
        uint32_t index = (ireg >> shift) & 0xff;
        if (index < maxindex) {
            uint32_t tmp = (table[index >> 3] >> ((index & 7) << 3)) & 0xff;
            val |= tmp << shift;
        } else {
            val |= def & (0xff << shift);
        }
    }
    return val;
}

#if !defined(CONFIG_USER_ONLY)

static inline uint32_t merge_syn_data_abort(uint32_t template_syn,
                                            unsigned int target_el,
                                            bool same_el, bool ea,
                                            bool s1ptw, bool is_write,
                                            int fsc)
{
    uint32_t syn;

    /* ISV is only set for data aborts routed to EL2 and
     * never for stage-1 page table walks faulting on stage 2.
     *
     * Furthermore, ISV is only set for certain kinds of load/stores.
     * If the template syndrome does not have ISV set, we should leave
     * it cleared.
     *
     * See ARMv8 specs, D7-1974:
     * ISS encoding for an exception from a Data Abort, the
     * ISV field.
     */
    if (!(template_syn & ARM_EL_ISV) || target_el != 2 || s1ptw) {
        syn = syn_data_abort_no_iss(same_el,
                                    ea, 0, s1ptw, is_write, fsc);
    } else {
        /* Fields: IL, ISV, SAS, SSE, SRT, SF and AR come from the template
         * syndrome created at translation time.
         * Now we create the runtime syndrome with the remaining fields.
         */
        syn = syn_data_abort_with_iss(same_el,
                                      0, 0, 0, 0, 0,
                                      ea, 0, s1ptw, is_write, fsc,
                                      false);
        /* Merge the runtime syndrome with the template syndrome.  */
        syn |= template_syn;
    }
    return syn;
}

static void deliver_fault(ARMCPU *cpu, vaddr addr, MMUAccessType access_type,
                          int mmu_idx, ARMMMUFaultInfo *fi)
{
    CPUARMState *env = &cpu->env;
    int target_el;
    bool same_el;
    uint32_t syn, exc, fsr, fsc;
    ARMMMUIdx arm_mmu_idx = core_to_arm_mmu_idx(env, mmu_idx);

    target_el = exception_target_el(env);
    if (fi->stage2) {
        target_el = 2;
        env->cp15.hpfar_el2 = extract64(fi->s2addr, 12, 47) << 4;
    }
    same_el = (arm_current_el(env) == target_el);

    if (target_el == 2 || arm_el_is_aa64(env, target_el) ||
        arm_s1_regime_using_lpae_format(env, arm_mmu_idx)) {
        /* LPAE format fault status register : bottom 6 bits are
         * status code in the same form as needed for syndrome
         */
        fsr = arm_fi_to_lfsc(fi);
        fsc = extract32(fsr, 0, 6);
    } else {
        fsr = arm_fi_to_sfsc(fi);
        /* Short format FSR : this fault will never actually be reported
         * to an EL that uses a syndrome register. Use a (currently)
         * reserved FSR code in case the constructed syndrome does leak
         * into the guest somehow.
         */
        fsc = 0x3f;
    }

    if (access_type == MMU_INST_FETCH) {
        syn = syn_insn_abort(same_el, fi->ea, fi->s1ptw, fsc);
        exc = EXCP_PREFETCH_ABORT;
    } else {
        syn = merge_syn_data_abort(env->exception.syndrome, target_el,
                                   same_el, fi->ea, fi->s1ptw,
                                   access_type == MMU_DATA_STORE,
                                   fsc);
        if (access_type == MMU_DATA_STORE
            && arm_feature(env, ARM_FEATURE_V6)) {
            fsr |= (1 << 11);
        }
        exc = EXCP_DATA_ABORT;
    }

    env->exception.vaddress = addr;
    env->exception.fsr = fsr;
    raise_exception(env, exc, syn, target_el);
}

/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
void tlb_fill(CPUState *cs, target_ulong addr, int size,
              MMUAccessType access_type, int mmu_idx, uintptr_t retaddr)
{
    bool ret;
    ARMMMUFaultInfo fi = {};

    ret = arm_tlb_fill(cs, addr, access_type, mmu_idx, &fi);
    if (unlikely(ret)) {
        ARMCPU *cpu = ARM_CPU(cs);

        /* now we have a real cpu fault */
        cpu_restore_state(cs, retaddr, true);

        deliver_fault(cpu, addr, access_type, mmu_idx, &fi);
    }
}

/* Raise a data fault alignment exception for the specified virtual address */
void arm_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                 MMUAccessType access_type,
                                 int mmu_idx, uintptr_t retaddr)
{
    ARMCPU *cpu = ARM_CPU(cs);
    ARMMMUFaultInfo fi = {};

    /* now we have a real cpu fault */
    cpu_restore_state(cs, retaddr, true);

    fi.type = ARMFault_Alignment;
    deliver_fault(cpu, vaddr, access_type, mmu_idx, &fi);
}

/* arm_cpu_do_transaction_failed: handle a memory system error response
 * (eg "no device/memory present at address") by raising an external abort
 * exception
 */
void arm_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr,
                                   vaddr addr, unsigned size,
                                   MMUAccessType access_type,
                                   int mmu_idx, MemTxAttrs attrs,
                                   MemTxResult response, uintptr_t retaddr)
{
    ARMCPU *cpu = ARM_CPU(cs);
    ARMMMUFaultInfo fi = {};

    /* now we have a real cpu fault */
    cpu_restore_state(cs, retaddr, true);

    fi.ea = arm_extabort_type(response);
    fi.type = ARMFault_SyncExternal;
    deliver_fault(cpu, addr, access_type, mmu_idx, &fi);
}

#endif /* !defined(CONFIG_USER_ONLY) */

void HELPER(v8m_stackcheck)(CPUARMState *env, uint32_t newvalue)
{
    /*
     * Perform the v8M stack limit check for SP updates from translated code,
     * raising an exception if the limit is breached.
     */
    if (newvalue < v7m_sp_limit(env)) {
        CPUState *cs = CPU(arm_env_get_cpu(env));

        /*
         * Stack limit exceptions are a rare case, so rather than syncing
         * PC/condbits before the call, we use cpu_restore_state() to
         * get them right before raising the exception.
         */
        cpu_restore_state(cs, GETPC(), true);
        raise_exception(env, EXCP_STKOF, 0, 1);
    }
}

uint32_t HELPER(add_setq)(CPUARMState *env, uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT))
        env->QF = 1;
    return res;
}

uint32_t HELPER(add_saturate)(CPUARMState *env, uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t)a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(sub_saturate)(CPUARMState *env, uint32_t a, uint32_t b)
{
    uint32_t res = a - b;
    if (((res ^ a) & SIGNBIT) && ((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t)a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(double_saturate)(CPUARMState *env, int32_t val)
{
    uint32_t res;
    if (val >= 0x40000000) {
        res = ~SIGNBIT;
        env->QF = 1;
    } else if (val <= (int32_t)0xc0000000) {
        res = SIGNBIT;
        env->QF = 1;
    } else {
        res = val << 1;
    }
    return res;
}

uint32_t HELPER(add_usaturate)(CPUARMState *env, uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (res < a) {
        env->QF = 1;
        res = ~0;
    }
    return res;
}

uint32_t HELPER(sub_usaturate)(CPUARMState *env, uint32_t a, uint32_t b)
{
    uint32_t res = a - b;
    if (res > a) {
        env->QF = 1;
        res = 0;
    }
    return res;
}

/* Signed saturation.  */
static inline uint32_t do_ssat(CPUARMState *env, int32_t val, int shift)
{
    int32_t top;
    uint32_t mask;

    top = val >> shift;
    mask = (1u << shift) - 1;
    if (top > 0) {
        env->QF = 1;
        return mask;
    } else if (top < -1) {
        env->QF = 1;
        return ~mask;
    }
    return val;
}

/* Unsigned saturation.  */
static inline uint32_t do_usat(CPUARMState *env, int32_t val, int shift)
{
    uint32_t max;

    max = (1u << shift) - 1;
    if (val < 0) {
        env->QF = 1;
        return 0;
    } else if (val > max) {
        env->QF = 1;
        return max;
    }
    return val;
}

/* Signed saturate.  */
uint32_t HELPER(ssat)(CPUARMState *env, uint32_t x, uint32_t shift)
{
    return do_ssat(env, x, shift);
}

/* Dual halfword signed saturate.  */
uint32_t HELPER(ssat16)(CPUARMState *env, uint32_t x, uint32_t shift)
{
    uint32_t res;

    res = (uint16_t)do_ssat(env, (int16_t)x, shift);
    res |= do_ssat(env, ((int32_t)x) >> 16, shift) << 16;
    return res;
}

/* Unsigned saturate.  */
uint32_t HELPER(usat)(CPUARMState *env, uint32_t x, uint32_t shift)
{
    return do_usat(env, x, shift);
}

/* Dual halfword unsigned saturate.  */
uint32_t HELPER(usat16)(CPUARMState *env, uint32_t x, uint32_t shift)
{
    uint32_t res;

    res = (uint16_t)do_usat(env, (int16_t)x, shift);
    res |= do_usat(env, ((int32_t)x) >> 16, shift) << 16;
    return res;
}

void HELPER(setend)(CPUARMState *env)
{
    env->uncached_cpsr ^= CPSR_E;
}

/* Function checks whether WFx (WFI/WFE) instructions are set up to be trapped.
 * The function returns the target EL (1-3) if the instruction is to be trapped;
 * otherwise it returns 0 indicating it is not trapped.
 */
static inline int check_wfx_trap(CPUARMState *env, bool is_wfe)
{
    int cur_el = arm_current_el(env);
    uint64_t mask;

    if (arm_feature(env, ARM_FEATURE_M)) {
        /* M profile cores can never trap WFI/WFE. */
        return 0;
    }

    /* If we are currently in EL0 then we need to check if SCTLR is set up for
     * WFx instructions being trapped to EL1. These trap bits don't exist in v7.
     */
    if (cur_el < 1 && arm_feature(env, ARM_FEATURE_V8)) {
        int target_el;

        mask = is_wfe ? SCTLR_nTWE : SCTLR_nTWI;
        if (arm_is_secure_below_el3(env) && !arm_el_is_aa64(env, 3)) {
            /* Secure EL0 and Secure PL1 is at EL3 */
            target_el = 3;
        } else {
            target_el = 1;
        }

        if (!(env->cp15.sctlr_el[target_el] & mask)) {
            return target_el;
        }
    }

    /* We are not trapping to EL1; trap to EL2 if HCR_EL2 requires it
     * No need for ARM_FEATURE check as if HCR_EL2 doesn't exist the
     * bits will be zero indicating no trap.
     */
    if (cur_el < 2) {
        mask = is_wfe ? HCR_TWE : HCR_TWI;
        if (arm_hcr_el2_eff(env) & mask) {
            return 2;
        }
    }

    /* We are not trapping to EL1 or EL2; trap to EL3 if SCR_EL3 requires it */
    if (cur_el < 3) {
        mask = (is_wfe) ? SCR_TWE : SCR_TWI;
        if (env->cp15.scr_el3 & mask) {
            return 3;
        }
    }

    return 0;
}

void HELPER(wfi)(CPUARMState *env, uint32_t insn_len)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int target_el = check_wfx_trap(env, false);

    if (cpu_has_work(cs)) {
        /* Don't bother to go into our "low power state" if
         * we would just wake up immediately.
         */
        return;
    }

    if (target_el) {
        env->pc -= insn_len;
        raise_exception(env, EXCP_UDEF, syn_wfx(1, 0xe, 0, insn_len == 2),
                        target_el);
    }

    cs->exception_index = EXCP_HLT;
    cs->halted = 1;
    cpu_loop_exit(cs);
}

void HELPER(wfe)(CPUARMState *env)
{
    /* This is a hint instruction that is semantically different
     * from YIELD even though we currently implement it identically.
     * Don't actually halt the CPU, just yield back to top
     * level loop. This is not going into a "low power state"
     * (ie halting until some event occurs), so we never take
     * a configurable trap to a different exception level.
     */
    HELPER(yield)(env);
}

void HELPER(yield)(CPUARMState *env)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    /* This is a non-trappable hint instruction that generally indicates
     * that the guest is currently busy-looping. Yield control back to the
     * top level loop so that a more deserving VCPU has a chance to run.
     */
    cs->exception_index = EXCP_YIELD;
    cpu_loop_exit(cs);
}

/* Raise an internal-to-QEMU exception. This is limited to only
 * those EXCP values which are special cases for QEMU to interrupt
 * execution and not to be used for exceptions which are passed to
 * the guest (those must all have syndrome information and thus should
 * use exception_with_syndrome).
 */
void HELPER(exception_internal)(CPUARMState *env, uint32_t excp)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));

    assert(excp_is_internal(excp));
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

/* Raise an exception with the specified syndrome register value */
void HELPER(exception_with_syndrome)(CPUARMState *env, uint32_t excp,
                                     uint32_t syndrome, uint32_t target_el)
{
    raise_exception(env, excp, syndrome, target_el);
}

/* Raise an EXCP_BKPT with the specified syndrome register value,
 * targeting the correct exception level for debug exceptions.
 */
void HELPER(exception_bkpt_insn)(CPUARMState *env, uint32_t syndrome)
{
    /* FSR will only be used if the debug target EL is AArch32. */
    env->exception.fsr = arm_debug_exception_fsr(env);
    /* FAR is UNKNOWN: clear vaddress to avoid potentially exposing
     * values to the guest that it shouldn't be able to see at its
     * exception/security level.
     */
    env->exception.vaddress = 0;
    raise_exception(env, EXCP_BKPT, syndrome, arm_debug_target_el(env));
}

uint32_t HELPER(cpsr_read)(CPUARMState *env)
{
    return cpsr_read(env) & ~(CPSR_EXEC | CPSR_RESERVED);
}

void HELPER(cpsr_write)(CPUARMState *env, uint32_t val, uint32_t mask)
{
    cpsr_write(env, val, mask, CPSRWriteByInstr);
}

/* Write the CPSR for a 32-bit exception return */
void HELPER(cpsr_write_eret)(CPUARMState *env, uint32_t val)
{
    qemu_mutex_lock_iothread();
    arm_call_pre_el_change_hook(arm_env_get_cpu(env));
    qemu_mutex_unlock_iothread();

    cpsr_write(env, val, CPSR_ERET_MASK, CPSRWriteExceptionReturn);

    /* Generated code has already stored the new PC value, but
     * without masking out its low bits, because which bits need
     * masking depends on whether we're returning to Thumb or ARM
     * state. Do the masking now.
     */
    env->regs[15] &= (env->thumb ? ~1 : ~3);

    qemu_mutex_lock_iothread();
    arm_call_el_change_hook(arm_env_get_cpu(env));
    qemu_mutex_unlock_iothread();
}

/* Access to user mode registers from privileged modes.  */
uint32_t HELPER(get_user_reg)(CPUARMState *env, uint32_t regno)
{
    uint32_t val;

    if (regno == 13) {
        val = env->banked_r13[BANK_USRSYS];
    } else if (regno == 14) {
        val = env->banked_r14[BANK_USRSYS];
    } else if (regno >= 8
               && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        val = env->usr_regs[regno - 8];
    } else {
        val = env->regs[regno];
    }
    return val;
}

void HELPER(set_user_reg)(CPUARMState *env, uint32_t regno, uint32_t val)
{
    if (regno == 13) {
        env->banked_r13[BANK_USRSYS] = val;
    } else if (regno == 14) {
        env->banked_r14[BANK_USRSYS] = val;
    } else if (regno >= 8
               && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        env->usr_regs[regno - 8] = val;
    } else {
        env->regs[regno] = val;
    }
}

void HELPER(set_r13_banked)(CPUARMState *env, uint32_t mode, uint32_t val)
{
    if ((env->uncached_cpsr & CPSR_M) == mode) {
        env->regs[13] = val;
    } else {
        env->banked_r13[bank_number(mode)] = val;
    }
}

uint32_t HELPER(get_r13_banked)(CPUARMState *env, uint32_t mode)
{
    if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SYS) {
        /* SRS instruction is UNPREDICTABLE from System mode; we UNDEF.
         * Other UNPREDICTABLE and UNDEF cases were caught at translate time.
         */
        raise_exception(env, EXCP_UDEF, syn_uncategorized(),
                        exception_target_el(env));
    }

    if ((env->uncached_cpsr & CPSR_M) == mode) {
        return env->regs[13];
    } else {
        return env->banked_r13[bank_number(mode)];
    }
}

static void msr_mrs_banked_exc_checks(CPUARMState *env, uint32_t tgtmode,
                                      uint32_t regno)
{
    /* Raise an exception if the requested access is one of the UNPREDICTABLE
     * cases; otherwise return. This broadly corresponds to the pseudocode
     * BankedRegisterAccessValid() and SPSRAccessValid(),
     * except that we have already handled some cases at translate time.
     */
    int curmode = env->uncached_cpsr & CPSR_M;

    if (regno == 17) {
        /* ELR_Hyp: a special case because access from tgtmode is OK */
        if (curmode != ARM_CPU_MODE_HYP && curmode != ARM_CPU_MODE_MON) {
            goto undef;
        }
        return;
    }

    if (curmode == tgtmode) {
        goto undef;
    }

    if (tgtmode == ARM_CPU_MODE_USR) {
        switch (regno) {
        case 8 ... 12:
            if (curmode != ARM_CPU_MODE_FIQ) {
                goto undef;
            }
            break;
        case 13:
            if (curmode == ARM_CPU_MODE_SYS) {
                goto undef;
            }
            break;
        case 14:
            if (curmode == ARM_CPU_MODE_HYP || curmode == ARM_CPU_MODE_SYS) {
                goto undef;
            }
            break;
        default:
            break;
        }
    }

    if (tgtmode == ARM_CPU_MODE_HYP) {
        /* SPSR_Hyp, r13_hyp: accessible from Monitor mode only */
        if (curmode != ARM_CPU_MODE_MON) {
            goto undef;
        }
    }

    return;

undef:
    raise_exception(env, EXCP_UDEF, syn_uncategorized(),
                    exception_target_el(env));
}

void HELPER(msr_banked)(CPUARMState *env, uint32_t value, uint32_t tgtmode,
                        uint32_t regno)
{
    msr_mrs_banked_exc_checks(env, tgtmode, regno);

    switch (regno) {
    case 16: /* SPSRs */
        env->banked_spsr[bank_number(tgtmode)] = value;
        break;
    case 17: /* ELR_Hyp */
        env->elr_el[2] = value;
        break;
    case 13:
        env->banked_r13[bank_number(tgtmode)] = value;
        break;
    case 14:
        env->banked_r14[r14_bank_number(tgtmode)] = value;
        break;
    case 8 ... 12:
        switch (tgtmode) {
        case ARM_CPU_MODE_USR:
            env->usr_regs[regno - 8] = value;
            break;
        case ARM_CPU_MODE_FIQ:
            env->fiq_regs[regno - 8] = value;
            break;
        default:
            g_assert_not_reached();
        }
        break;
    default:
        g_assert_not_reached();
    }
}

uint32_t HELPER(mrs_banked)(CPUARMState *env, uint32_t tgtmode, uint32_t regno)
{
    msr_mrs_banked_exc_checks(env, tgtmode, regno);

    switch (regno) {
    case 16: /* SPSRs */
        return env->banked_spsr[bank_number(tgtmode)];
    case 17: /* ELR_Hyp */
        return env->elr_el[2];
    case 13:
        return env->banked_r13[bank_number(tgtmode)];
    case 14:
        return env->banked_r14[r14_bank_number(tgtmode)];
    case 8 ... 12:
        switch (tgtmode) {
        case ARM_CPU_MODE_USR:
            return env->usr_regs[regno - 8];
        case ARM_CPU_MODE_FIQ:
            return env->fiq_regs[regno - 8];
        default:
            g_assert_not_reached();
        }
    default:
        g_assert_not_reached();
    }
}

void HELPER(access_check_cp_reg)(CPUARMState *env, void *rip, uint32_t syndrome,
                                 uint32_t isread)
{
    const ARMCPRegInfo *ri = rip;
    int target_el;

    if (arm_feature(env, ARM_FEATURE_XSCALE) && ri->cp < 14
        && extract32(env->cp15.c15_cpar, ri->cp, 1) == 0) {
        raise_exception(env, EXCP_UDEF, syndrome, exception_target_el(env));
    }

    if (!ri->accessfn) {
        return;
    }

    switch (ri->accessfn(env, ri, isread)) {
    case CP_ACCESS_OK:
        return;
    case CP_ACCESS_TRAP:
        target_el = exception_target_el(env);
        break;
    case CP_ACCESS_TRAP_EL2:
        /* Requesting a trap to EL2 when we're in EL3 or S-EL0/1 is
         * a bug in the access function.
         */
        assert(!arm_is_secure(env) && arm_current_el(env) != 3);
        target_el = 2;
        break;
    case CP_ACCESS_TRAP_EL3:
        target_el = 3;
        break;
    case CP_ACCESS_TRAP_UNCATEGORIZED:
        target_el = exception_target_el(env);
        syndrome = syn_uncategorized();
        break;
    case CP_ACCESS_TRAP_UNCATEGORIZED_EL2:
        target_el = 2;
        syndrome = syn_uncategorized();
        break;
    case CP_ACCESS_TRAP_UNCATEGORIZED_EL3:
        target_el = 3;
        syndrome = syn_uncategorized();
        break;
    case CP_ACCESS_TRAP_FP_EL2:
        target_el = 2;
        /* Since we are an implementation that takes exceptions on a trapped
         * conditional insn only if the insn has passed its condition code
         * check, we take the IMPDEF choice to always report CV=1 COND=0xe
         * (which is also the required value for AArch64 traps).
         */
        syndrome = syn_fp_access_trap(1, 0xe, false);
        break;
    case CP_ACCESS_TRAP_FP_EL3:
        target_el = 3;
        syndrome = syn_fp_access_trap(1, 0xe, false);
        break;
    default:
        g_assert_not_reached();
    }

    raise_exception(env, EXCP_UDEF, syndrome, target_el);
}

void HELPER(set_cp_reg)(CPUARMState *env, void *rip, uint32_t value)
{
    const ARMCPRegInfo *ri = rip;

    if (ri->type & ARM_CP_IO) {
        qemu_mutex_lock_iothread();
        ri->writefn(env, ri, value);
        qemu_mutex_unlock_iothread();
    } else {
        ri->writefn(env, ri, value);
    }
}

uint32_t HELPER(get_cp_reg)(CPUARMState *env, void *rip)
{
    const ARMCPRegInfo *ri = rip;
    uint32_t res;

    if (ri->type & ARM_CP_IO) {
        qemu_mutex_lock_iothread();
        res = ri->readfn(env, ri);
        qemu_mutex_unlock_iothread();
    } else {
        res = ri->readfn(env, ri);
    }

    return res;
}

void HELPER(set_cp_reg64)(CPUARMState *env, void *rip, uint64_t value)
{
    const ARMCPRegInfo *ri = rip;

    if (ri->type & ARM_CP_IO) {
        qemu_mutex_lock_iothread();
        ri->writefn(env, ri, value);
        qemu_mutex_unlock_iothread();
    } else {
        ri->writefn(env, ri, value);
    }
}

uint64_t HELPER(get_cp_reg64)(CPUARMState *env, void *rip)
{
    const ARMCPRegInfo *ri = rip;
    uint64_t res;

    if (ri->type & ARM_CP_IO) {
        qemu_mutex_lock_iothread();
        res = ri->readfn(env, ri);
        qemu_mutex_unlock_iothread();
    } else {
        res = ri->readfn(env, ri);
    }

    return res;
}

void HELPER(pre_hvc)(CPUARMState *env)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int cur_el = arm_current_el(env);
    /* FIXME: Use actual secure state.  */
    bool secure = false;
    bool undef;

    if (arm_is_psci_call(cpu, EXCP_HVC)) {
        /* If PSCI is enabled and this looks like a valid PSCI call then
         * that overrides the architecturally mandated HVC behaviour.
         */
        return;
    }

    if (!arm_feature(env, ARM_FEATURE_EL2)) {
        /* If EL2 doesn't exist, HVC always UNDEFs */
        undef = true;
    } else if (arm_feature(env, ARM_FEATURE_EL3)) {
        /* EL3.HCE has priority over EL2.HCD. */
        undef = !(env->cp15.scr_el3 & SCR_HCE);
    } else {
        undef = env->cp15.hcr_el2 & HCR_HCD;
    }

    /* In ARMv7 and ARMv8/AArch32, HVC is undef in secure state.
     * For ARMv8/AArch64, HVC is allowed in EL3.
     * Note that we've already trapped HVC from EL0 at translation
     * time.
     */
    if (secure && (!is_a64(env) || cur_el == 1)) {
        undef = true;
    }

    if (undef) {
        raise_exception(env, EXCP_UDEF, syn_uncategorized(),
                        exception_target_el(env));
    }
}

void HELPER(pre_smc)(CPUARMState *env, uint32_t syndrome)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);
    bool smd_flag = env->cp15.scr_el3 & SCR_SMD;

    /*
     * SMC behaviour is summarized in the following table.
     * This helper handles the "Trap to EL2" and "Undef insn" cases.
     * The "Trap to EL3" and "PSCI call" cases are handled in the exception
     * helper.
     *
     *  -> ARM_FEATURE_EL3 and !SMD
     *                           HCR_TSC && NS EL1   !HCR_TSC || !NS EL1
     *
     *  Conduit SMC, valid call  Trap to EL2         PSCI Call
     *  Conduit SMC, inval call  Trap to EL2         Trap to EL3
     *  Conduit not SMC          Trap to EL2         Trap to EL3
     *
     *
     *  -> ARM_FEATURE_EL3 and SMD
     *                           HCR_TSC && NS EL1   !HCR_TSC || !NS EL1
     *
     *  Conduit SMC, valid call  Trap to EL2         PSCI Call
     *  Conduit SMC, inval call  Trap to EL2         Undef insn
     *  Conduit not SMC          Trap to EL2         Undef insn
     *
     *
     *  -> !ARM_FEATURE_EL3
     *                           HCR_TSC && NS EL1   !HCR_TSC || !NS EL1
     *
     *  Conduit SMC, valid call  Trap to EL2         PSCI Call
     *  Conduit SMC, inval call  Trap to EL2         Undef insn
     *  Conduit not SMC          Undef insn          Undef insn
     */

    /* On ARMv8 with EL3 AArch64, SMD applies to both S and NS state.
     * On ARMv8 with EL3 AArch32, or ARMv7 with the Virtualization
     *  extensions, SMD only applies to NS state.
     * On ARMv7 without the Virtualization extensions, the SMD bit
     * doesn't exist, but we forbid the guest to set it to 1 in scr_write(),
     * so we need not special case this here.
     */
    bool smd = arm_feature(env, ARM_FEATURE_AARCH64) ? smd_flag
                                                     : smd_flag && !secure;

    if (!arm_feature(env, ARM_FEATURE_EL3) &&
        cpu->psci_conduit != QEMU_PSCI_CONDUIT_SMC) {
        /* If we have no EL3 then SMC always UNDEFs and can't be
         * trapped to EL2. PSCI-via-SMC is a sort of ersatz EL3
         * firmware within QEMU, and we want an EL2 guest to be able
         * to forbid its EL1 from making PSCI calls into QEMU's
         * "firmware" via HCR.TSC, so for these purposes treat
         * PSCI-via-SMC as implying an EL3.
         * This handles the very last line of the previous table.
         */
        raise_exception(env, EXCP_UDEF, syn_uncategorized(),
                        exception_target_el(env));
    }

    if (cur_el == 1 && (arm_hcr_el2_eff(env) & HCR_TSC)) {
        /* In NS EL1, HCR controlled routing to EL2 has priority over SMD.
         * We also want an EL2 guest to be able to forbid its EL1 from
         * making PSCI calls into QEMU's "firmware" via HCR.TSC.
         * This handles all the "Trap to EL2" cases of the previous table.
         */
        raise_exception(env, EXCP_HYP_TRAP, syndrome, 2);
    }

    /* Catch the two remaining "Undef insn" cases of the previous table:
     *    - PSCI conduit is SMC but we don't have a valid PCSI call,
     *    - We don't have EL3 or SMD is set.
     */
    if (!arm_is_psci_call(cpu, EXCP_SMC) &&
        (smd || !arm_feature(env, ARM_FEATURE_EL3))) {
        raise_exception(env, EXCP_UDEF, syn_uncategorized(),
                        exception_target_el(env));
    }
}

/* Return true if the linked breakpoint entry lbn passes its checks */
static bool linked_bp_matches(ARMCPU *cpu, int lbn)
{
    CPUARMState *env = &cpu->env;
    uint64_t bcr = env->cp15.dbgbcr[lbn];
    int brps = extract32(cpu->dbgdidr, 24, 4);
    int ctx_cmps = extract32(cpu->dbgdidr, 20, 4);
    int bt;
    uint32_t contextidr;

    /* Links to unimplemented or non-context aware breakpoints are
     * CONSTRAINED UNPREDICTABLE: either behave as if disabled, or
     * as if linked to an UNKNOWN context-aware breakpoint (in which
     * case DBGWCR<n>_EL1.LBN must indicate that breakpoint).
     * We choose the former.
     */
    if (lbn > brps || lbn < (brps - ctx_cmps)) {
        return false;
    }

    bcr = env->cp15.dbgbcr[lbn];

    if (extract64(bcr, 0, 1) == 0) {
        /* Linked breakpoint disabled : generate no events */
        return false;
    }

    bt = extract64(bcr, 20, 4);

    /* We match the whole register even if this is AArch32 using the
     * short descriptor format (in which case it holds both PROCID and ASID),
     * since we don't implement the optional v7 context ID masking.
     */
    contextidr = extract64(env->cp15.contextidr_el[1], 0, 32);

    switch (bt) {
    case 3: /* linked context ID match */
        if (arm_current_el(env) > 1) {
            /* Context matches never fire in EL2 or (AArch64) EL3 */
            return false;
        }
        return (contextidr == extract64(env->cp15.dbgbvr[lbn], 0, 32));
    case 5: /* linked address mismatch (reserved in AArch64) */
    case 9: /* linked VMID match (reserved if no EL2) */
    case 11: /* linked context ID and VMID match (reserved if no EL2) */
    default:
        /* Links to Unlinked context breakpoints must generate no
         * events; we choose to do the same for reserved values too.
         */
        return false;
    }

    return false;
}

static bool bp_wp_matches(ARMCPU *cpu, int n, bool is_wp)
{
    CPUARMState *env = &cpu->env;
    uint64_t cr;
    int pac, hmc, ssc, wt, lbn;
    /* Note that for watchpoints the check is against the CPU security
     * state, not the S/NS attribute on the offending data access.
     */
    bool is_secure = arm_is_secure(env);
    int access_el = arm_current_el(env);

    if (is_wp) {
        CPUWatchpoint *wp = env->cpu_watchpoint[n];

        if (!wp || !(wp->flags & BP_WATCHPOINT_HIT)) {
            return false;
        }
        cr = env->cp15.dbgwcr[n];
        if (wp->hitattrs.user) {
            /* The LDRT/STRT/LDT/STT "unprivileged access" instructions should
             * match watchpoints as if they were accesses done at EL0, even if
             * the CPU is at EL1 or higher.
             */
            access_el = 0;
        }
    } else {
        uint64_t pc = is_a64(env) ? env->pc : env->regs[15];

        if (!env->cpu_breakpoint[n] || env->cpu_breakpoint[n]->pc != pc) {
            return false;
        }
        cr = env->cp15.dbgbcr[n];
    }
    /* The WATCHPOINT_HIT flag guarantees us that the watchpoint is
     * enabled and that the address and access type match; for breakpoints
     * we know the address matched; check the remaining fields, including
     * linked breakpoints. We rely on WCR and BCR having the same layout
     * for the LBN, SSC, HMC, PAC/PMC and is-linked fields.
     * Note that some combinations of {PAC, HMC, SSC} are reserved and
     * must act either like some valid combination or as if the watchpoint
     * were disabled. We choose the former, and use this together with
     * the fact that EL3 must always be Secure and EL2 must always be
     * Non-Secure to simplify the code slightly compared to the full
     * table in the ARM ARM.
     */
    pac = extract64(cr, 1, 2);
    hmc = extract64(cr, 13, 1);
    ssc = extract64(cr, 14, 2);

    switch (ssc) {
    case 0:
        break;
    case 1:
    case 3:
        if (is_secure) {
            return false;
        }
        break;
    case 2:
        if (!is_secure) {
            return false;
        }
        break;
    }

    switch (access_el) {
    case 3:
    case 2:
        if (!hmc) {
            return false;
        }
        break;
    case 1:
        if (extract32(pac, 0, 1) == 0) {
            return false;
        }
        break;
    case 0:
        if (extract32(pac, 1, 1) == 0) {
            return false;
        }
        break;
    default:
        g_assert_not_reached();
    }

    wt = extract64(cr, 20, 1);
    lbn = extract64(cr, 16, 4);

    if (wt && !linked_bp_matches(cpu, lbn)) {
        return false;
    }

    return true;
}

static bool check_watchpoints(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    int n;

    /* If watchpoints are disabled globally or we can't take debug
     * exceptions here then watchpoint firings are ignored.
     */
    if (extract32(env->cp15.mdscr_el1, 15, 1) == 0
        || !arm_generate_debug_exceptions(env)) {
        return false;
    }

    for (n = 0; n < ARRAY_SIZE(env->cpu_watchpoint); n++) {
        if (bp_wp_matches(cpu, n, true)) {
            return true;
        }
    }
    return false;
}

static bool check_breakpoints(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    int n;

    /* If breakpoints are disabled globally or we can't take debug
     * exceptions here then breakpoint firings are ignored.
     */
    if (extract32(env->cp15.mdscr_el1, 15, 1) == 0
        || !arm_generate_debug_exceptions(env)) {
        return false;
    }

    for (n = 0; n < ARRAY_SIZE(env->cpu_breakpoint); n++) {
        if (bp_wp_matches(cpu, n, false)) {
            return true;
        }
    }
    return false;
}

void HELPER(check_breakpoints)(CPUARMState *env)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (check_breakpoints(cpu)) {
        HELPER(exception_internal(env, EXCP_DEBUG));
    }
}

bool arm_debug_check_watchpoint(CPUState *cs, CPUWatchpoint *wp)
{
    /* Called by core code when a CPU watchpoint fires; need to check if this
     * is also an architectural watchpoint match.
     */
    ARMCPU *cpu = ARM_CPU(cs);

    return check_watchpoints(cpu);
}

vaddr arm_adjust_watchpoint_address(CPUState *cs, vaddr addr, int len)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    /* In BE32 system mode, target memory is stored byteswapped (on a
     * little-endian host system), and by the time we reach here (via an
     * opcode helper) the addresses of subword accesses have been adjusted
     * to account for that, which means that watchpoints will not match.
     * Undo the adjustment here.
     */
    if (arm_sctlr_b(env)) {
        if (len == 1) {
            addr ^= 3;
        } else if (len == 2) {
            addr ^= 2;
        }
    }

    return addr;
}

void arm_debug_excp_handler(CPUState *cs)
{
    /* Called by core code when a watchpoint or breakpoint fires;
     * need to check which one and raise the appropriate exception.
     */
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    CPUWatchpoint *wp_hit = cs->watchpoint_hit;

    if (wp_hit) {
        if (wp_hit->flags & BP_CPU) {
            bool wnr = (wp_hit->flags & BP_WATCHPOINT_HIT_WRITE) != 0;
            bool same_el = arm_debug_target_el(env) == arm_current_el(env);

            cs->watchpoint_hit = NULL;

            env->exception.fsr = arm_debug_exception_fsr(env);
            env->exception.vaddress = wp_hit->hitaddr;
            raise_exception(env, EXCP_DATA_ABORT,
                    syn_watchpoint(same_el, 0, wnr),
                    arm_debug_target_el(env));
        }
    } else {
        uint64_t pc = is_a64(env) ? env->pc : env->regs[15];
        bool same_el = (arm_debug_target_el(env) == arm_current_el(env));

        /* (1) GDB breakpoints should be handled first.
         * (2) Do not raise a CPU exception if no CPU breakpoint has fired,
         * since singlestep is also done by generating a debug internal
         * exception.
         */
        if (cpu_breakpoint_test(cs, pc, BP_GDB)
            || !cpu_breakpoint_test(cs, pc, BP_CPU)) {
            return;
        }

        env->exception.fsr = arm_debug_exception_fsr(env);
        /* FAR is UNKNOWN: clear vaddress to avoid potentially exposing
         * values to the guest that it shouldn't be able to see at its
         * exception/security level.
         */
        env->exception.vaddress = 0;
        raise_exception(env, EXCP_PREFETCH_ABORT,
                        syn_breakpoint(same_el),
                        arm_debug_target_el(env));
    }
}

/* ??? Flag setting arithmetic is awkward because we need to do comparisons.
   The only way to do that in TCG is a conditional branch, which clobbers
   all our temporaries.  For now implement these as helper functions.  */

/* Similarly for variable shift instructions.  */

uint32_t HELPER(shl_cc)(CPUARMState *env, uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            env->CF = x & 1;
        else
            env->CF = 0;
        return 0;
    } else if (shift != 0) {
        env->CF = (x >> (32 - shift)) & 1;
        return x << shift;
    }
    return x;
}

uint32_t HELPER(shr_cc)(CPUARMState *env, uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            env->CF = (x >> 31) & 1;
        else
            env->CF = 0;
        return 0;
    } else if (shift != 0) {
        env->CF = (x >> (shift - 1)) & 1;
        return x >> shift;
    }
    return x;
}

uint32_t HELPER(sar_cc)(CPUARMState *env, uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        env->CF = (x >> 31) & 1;
        return (int32_t)x >> 31;
    } else if (shift != 0) {
        env->CF = (x >> (shift - 1)) & 1;
        return (int32_t)x >> shift;
    }
    return x;
}

uint32_t HELPER(ror_cc)(CPUARMState *env, uint32_t x, uint32_t i)
{
    int shift1, shift;
    shift1 = i & 0xff;
    shift = shift1 & 0x1f;
    if (shift == 0) {
        if (shift1 != 0)
            env->CF = (x >> 31) & 1;
        return x;
    } else {
        env->CF = (x >> (shift - 1)) & 1;
        return ((uint32_t)x >> shift) | (x << (32 - shift));
    }
}

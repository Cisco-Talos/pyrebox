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

/***********************************************************/
/* CPUX86 core interface */

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_host_ticks();
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
              int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
#ifdef TARGET_X86_64
static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}
#else
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
                     uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate(idt_table + n, 0, dpl, 0, 0);
}
#endif

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;
    abi_ulong pc;
    abi_ulong ret;
    target_siginfo_t info;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case 0x80:
            /* linux syscall from int $0x80 */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EBX],
                             env->regs[R_ECX],
                             env->regs[R_EDX],
                             env->regs[R_ESI],
                             env->regs[R_EDI],
                             env->regs[R_EBP],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
#ifndef TARGET_ABI32
        case EXCP_SYSCALL:
            /* linux syscall from syscall instruction */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EDI],
                             env->regs[R_ESI],
                             env->regs[R_EDX],
                             env->regs[10],
                             env->regs[8],
                             env->regs[9],
                             0, 0);
            if (ret == -TARGET_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -TARGET_QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
#endif
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = TARGET_SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP0E_PAGE:
            info.si_signo = TARGET_SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP00_DIVZ:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                /* division by zero */
                info.si_signo = TARGET_SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = TARGET_SIGTRAP;
                info.si_errno = 0;
                if (trapnr == EXCP01_DB) {
                    info.si_code = TARGET_TRAP_BRKPT;
                    info._sifields._sigfault._addr = env->eip;
                } else {
                    info.si_code = TARGET_SI_KERNEL;
                    info._sifields._sigfault._addr = 0;
                }
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP06_ILLOP:
            info.si_signo = TARGET_SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            info.si_signo = TARGET_SIGTRAP;
            info.si_errno = 0;
            info.si_code = TARGET_TRAP_BRKPT;
            queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            EXCP_DUMP(env, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                      (long)pc, trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
#ifndef TARGET_ABI32
    /* enable 64 bit mode if possible */
    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
#ifndef TARGET_ABI32
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_EBP] = regs->rbp;
    env->regs[R_ESP] = regs->rsp;
    env->eip = regs->rip;
#else
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
#endif

    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h(env->idt.base);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ|PROT_WRITE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
#ifdef TARGET_ABI32
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
    /* This hack makes Wine work... */
    env->segs[R_FS].selector = 0;
#else
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
#endif
}

/*
 *  Moxie emulation
 *
 *  Copyright (c) 2008, 2010, 2013 Anthony Green
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MOXIE_CPU_H
#define MOXIE_CPU_H

#include "qemu-common.h"

#define TARGET_LONG_BITS 32

#define CPUArchState struct CPUMoxieState

#define MOXIE_EX_DIV0        0
#define MOXIE_EX_BAD         1
#define MOXIE_EX_IRQ         2
#define MOXIE_EX_SWI         3
#define MOXIE_EX_MMU_MISS    4
#define MOXIE_EX_BREAK      16

#include "exec/cpu-defs.h"

#define TARGET_PAGE_BITS 12     /* 4k */

#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32

#define NB_MMU_MODES 1

typedef struct CPUMoxieState {

    uint32_t flags;               /* general execution flags */
    uint32_t gregs[16];           /* general registers */
    uint32_t sregs[256];          /* special registers */
    uint32_t pc;                  /* program counter */
    /* Instead of saving the cc value, we save the cmp arguments
       and compute cc on demand.  */
    uint32_t cc_a;                /* reg a for condition code calculation */
    uint32_t cc_b;                /* reg b for condition code calculation */

    void *irq[8];

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    CPU_COMMON

} CPUMoxieState;

#include "qom/cpu.h"

#define TYPE_MOXIE_CPU "moxie-cpu"

#define MOXIE_CPU_CLASS(klass) \
    OBJECT_CLASS_CHECK(MoxieCPUClass, (klass), TYPE_MOXIE_CPU)
#define MOXIE_CPU(obj) \
    OBJECT_CHECK(MoxieCPU, (obj), TYPE_MOXIE_CPU)
#define MOXIE_CPU_GET_CLASS(obj) \
    OBJECT_GET_CLASS(MoxieCPUClass, (obj), TYPE_MOXIE_CPU)

/**
 * MoxieCPUClass:
 * @parent_reset: The parent class' reset handler.
 *
 * A Moxie CPU model.
 */
typedef struct MoxieCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    void (*parent_reset)(CPUState *cpu);
} MoxieCPUClass;

/**
 * MoxieCPU:
 * @env: #CPUMoxieState
 *
 * A Moxie CPU.
 */
typedef struct MoxieCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUMoxieState env;
} MoxieCPU;

static inline MoxieCPU *moxie_env_get_cpu(CPUMoxieState *env)
{
    return container_of(env, MoxieCPU, env);
}

#define ENV_GET_CPU(e) CPU(moxie_env_get_cpu(e))

#define ENV_OFFSET offsetof(MoxieCPU, env)

void moxie_cpu_do_interrupt(CPUState *cs);
void moxie_cpu_dump_state(CPUState *cpu, FILE *f,
                          fprintf_function cpu_fprintf, int flags);
hwaddr moxie_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
void moxie_translate_init(void);
int cpu_moxie_signal_handler(int host_signum, void *pinfo,
                             void *puc);

#define MOXIE_CPU_TYPE_SUFFIX "-" TYPE_MOXIE_CPU
#define MOXIE_CPU_TYPE_NAME(model) model MOXIE_CPU_TYPE_SUFFIX
#define CPU_RESOLVING_TYPE TYPE_MOXIE_CPU

#define cpu_signal_handler cpu_moxie_signal_handler

static inline int cpu_mmu_index(CPUMoxieState *env, bool ifetch)
{
    return 0;
}

#include "exec/cpu-all.h"

static inline void cpu_get_tb_cpu_state(CPUMoxieState *env, target_ulong *pc,
                                        target_ulong *cs_base, uint32_t *flags)
{
    *pc = env->pc;
    *cs_base = 0;
    *flags = 0;
}

int moxie_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int size,
                               int rw, int mmu_idx);

#endif /* MOXIE_CPU_H */

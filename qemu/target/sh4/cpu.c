/*
 * QEMU SuperH CPU
 *
 * Copyright (c) 2005 Samuel Tardieu
 * Copyright (c) 2012 SUSE LINUX Products GmbH
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "qemu-common.h"
#include "migration/vmstate.h"
#include "exec/exec-all.h"
#include "fpu/softfloat.h"


static void superh_cpu_set_pc(CPUState *cs, vaddr value)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    cpu->env.pc = value;
}

static void superh_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    SuperHCPU *cpu = SUPERH_CPU(cs);

    cpu->env.pc = tb->pc;
    cpu->env.flags = tb->flags & TB_FLAG_ENVFLAGS_MASK;
}

static bool superh_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

/* CPUClass::reset() */
static void superh_cpu_reset(CPUState *s)
{
    SuperHCPU *cpu = SUPERH_CPU(s);
    SuperHCPUClass *scc = SUPERH_CPU_GET_CLASS(cpu);
    CPUSH4State *env = &cpu->env;

    scc->parent_reset(s);

    memset(env, 0, offsetof(CPUSH4State, end_reset_fields));

    env->pc = 0xA0000000;
#if defined(CONFIG_USER_ONLY)
    env->fpscr = FPSCR_PR; /* value for userspace according to the kernel */
    set_float_rounding_mode(float_round_nearest_even, &env->fp_status); /* ?! */
#else
    env->sr = (1u << SR_MD) | (1u << SR_RB) | (1u << SR_BL) |
              (1u << SR_I3) | (1u << SR_I2) | (1u << SR_I1) | (1u << SR_I0);
    env->fpscr = FPSCR_DN | FPSCR_RM_ZERO; /* CPU reset value according to SH4 manual */
    set_float_rounding_mode(float_round_to_zero, &env->fp_status);
    set_flush_to_zero(1, &env->fp_status);
#endif
    set_default_nan_mode(1, &env->fp_status);
}

static void superh_cpu_disas_set_info(CPUState *cpu, disassemble_info *info)
{
    info->mach = bfd_mach_sh4;
    info->print_insn = print_insn_sh;
}

typedef struct SuperHCPUListState {
    fprintf_function cpu_fprintf;
    FILE *file;
} SuperHCPUListState;

static void superh_cpu_list_entry(gpointer data, gpointer user_data)
{
    SuperHCPUListState *s = user_data;
    const char *typename = object_class_get_name(OBJECT_CLASS(data));
    int len = strlen(typename) - strlen(SUPERH_CPU_TYPE_SUFFIX);

    (*s->cpu_fprintf)(s->file, "%.*s\n", len, typename);
}

void sh4_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
    SuperHCPUListState s = {
        .cpu_fprintf = cpu_fprintf,
        .file = f,
    };
    GSList *list;

    list = object_class_get_list_sorted(TYPE_SUPERH_CPU, false);
    g_slist_foreach(list, superh_cpu_list_entry, &s);
    g_slist_free(list);
}

static ObjectClass *superh_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *s, *typename = NULL;

    s = g_ascii_strdown(cpu_model, -1);
    if (strcmp(s, "any") == 0) {
        oc = object_class_by_name(TYPE_SH7750R_CPU);
        goto out;
    }

    typename = g_strdup_printf(SUPERH_CPU_TYPE_NAME("%s"), s);
    oc = object_class_by_name(typename);
    if (oc != NULL && object_class_is_abstract(oc)) {
        oc = NULL;
    }

out:
    g_free(s);
    g_free(typename);
    return oc;
}

static void sh7750r_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7750R;
    env->features = SH_FEATURE_BCR3_AND_BCR4;
}

static void sh7750r_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x00050000;
    scc->prr = 0x00000100;
    scc->cvr = 0x00110000;
}

static void sh7751r_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7751R;
    env->features = SH_FEATURE_BCR3_AND_BCR4;
}

static void sh7751r_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x04050005;
    scc->prr = 0x00000113;
    scc->cvr = 0x00110000; /* Neutered caches, should be 0x20480000 */
}

static void sh7785_cpu_initfn(Object *obj)
{
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    env->id = SH_CPU_SH7785;
    env->features = SH_FEATURE_SH4A;
}

static void sh7785_class_init(ObjectClass *oc, void *data)
{
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    scc->pvr = 0x10300700;
    scc->prr = 0x00000200;
    scc->cvr = 0x71440211;
}

static void superh_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    SuperHCPUClass *scc = SUPERH_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    scc->parent_realize(dev, errp);
}

static void superh_cpu_initfn(Object *obj)
{
    CPUState *cs = CPU(obj);
    SuperHCPU *cpu = SUPERH_CPU(obj);
    CPUSH4State *env = &cpu->env;

    cs->env_ptr = env;

    env->movcal_backup_tail = &(env->movcal_backup);
}

static const VMStateDescription vmstate_sh_cpu = {
    .name = "cpu",
    .unmigratable = 1,
};

static void superh_cpu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    SuperHCPUClass *scc = SUPERH_CPU_CLASS(oc);

    device_class_set_parent_realize(dc, superh_cpu_realizefn,
                                    &scc->parent_realize);

    scc->parent_reset = cc->reset;
    cc->reset = superh_cpu_reset;

    cc->class_by_name = superh_cpu_class_by_name;
    cc->has_work = superh_cpu_has_work;
    cc->do_interrupt = superh_cpu_do_interrupt;
    cc->cpu_exec_interrupt = superh_cpu_exec_interrupt;
    cc->dump_state = superh_cpu_dump_state;
    cc->set_pc = superh_cpu_set_pc;
    cc->synchronize_from_tb = superh_cpu_synchronize_from_tb;
    cc->gdb_read_register = superh_cpu_gdb_read_register;
    cc->gdb_write_register = superh_cpu_gdb_write_register;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = superh_cpu_handle_mmu_fault;
#else
    cc->do_unaligned_access = superh_cpu_do_unaligned_access;
    cc->get_phys_page_debug = superh_cpu_get_phys_page_debug;
#endif
    cc->disas_set_info = superh_cpu_disas_set_info;
    cc->tcg_initialize = sh4_translate_init;

    cc->gdb_num_core_regs = 59;

    dc->vmsd = &vmstate_sh_cpu;
}

#define DEFINE_SUPERH_CPU_TYPE(type_name, cinit, initfn) \
    {                                                    \
        .name = type_name,                               \
        .parent = TYPE_SUPERH_CPU,                       \
        .class_init = cinit,                             \
        .instance_init = initfn,                         \
    }
static const TypeInfo superh_cpu_type_infos[] = {
    {
        .name = TYPE_SUPERH_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(SuperHCPU),
        .instance_init = superh_cpu_initfn,
        .abstract = true,
        .class_size = sizeof(SuperHCPUClass),
        .class_init = superh_cpu_class_init,
    },
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7750R_CPU, sh7750r_class_init,
                           sh7750r_cpu_initfn),
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7751R_CPU, sh7751r_class_init,
                           sh7751r_cpu_initfn),
    DEFINE_SUPERH_CPU_TYPE(TYPE_SH7785_CPU, sh7785_class_init,
                           sh7785_cpu_initfn),

};

DEFINE_TYPES(superh_cpu_type_infos)

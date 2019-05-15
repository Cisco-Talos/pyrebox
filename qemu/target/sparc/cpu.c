/*
 * Sparc CPU init helpers
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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
#include "qapi/error.h"
#include "cpu.h"
#include "qemu/error-report.h"
#include "exec/exec-all.h"
#include "hw/qdev-properties.h"
#include "qapi/visitor.h"

//#define DEBUG_FEATURES

/* CPUClass::reset() */
static void sparc_cpu_reset(CPUState *s)
{
    SPARCCPU *cpu = SPARC_CPU(s);
    SPARCCPUClass *scc = SPARC_CPU_GET_CLASS(cpu);
    CPUSPARCState *env = &cpu->env;

    scc->parent_reset(s);

    memset(env, 0, offsetof(CPUSPARCState, end_reset_fields));
    env->cwp = 0;
#ifndef TARGET_SPARC64
    env->wim = 1;
#endif
    env->regwptr = env->regbase + (env->cwp * 16);
    CC_OP = CC_OP_FLAGS;
#if defined(CONFIG_USER_ONLY)
#ifdef TARGET_SPARC64
    env->cleanwin = env->nwindows - 2;
    env->cansave = env->nwindows - 2;
    env->pstate = PS_RMO | PS_PEF | PS_IE;
    env->asi = 0x82; /* Primary no-fault */
#endif
#else
#if !defined(TARGET_SPARC64)
    env->psret = 0;
    env->psrs = 1;
    env->psrps = 1;
#endif
#ifdef TARGET_SPARC64
    env->pstate = PS_PRIV | PS_RED | PS_PEF;
    if (!cpu_has_hypervisor(env)) {
        env->pstate |= PS_AG;
    }
    env->hpstate = cpu_has_hypervisor(env) ? HS_PRIV : 0;
    env->tl = env->maxtl;
    env->gl = 2;
    cpu_tsptr(env)->tt = TT_POWER_ON_RESET;
    env->lsu = 0;
#else
    env->mmuregs[0] &= ~(MMU_E | MMU_NF);
    env->mmuregs[0] |= env->def.mmu_bm;
#endif
    env->pc = 0;
    env->npc = env->pc + 4;
#endif
    env->cache_control = 0;
}

static bool sparc_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        SPARCCPU *cpu = SPARC_CPU(cs);
        CPUSPARCState *env = &cpu->env;

        if (cpu_interrupts_enabled(env) && env->interrupt_index > 0) {
            int pil = env->interrupt_index & 0xf;
            int type = env->interrupt_index & 0xf0;

            if (type != TT_EXTINT || cpu_pil_allowed(env, pil)) {
                cs->exception_index = env->interrupt_index;
                sparc_cpu_do_interrupt(cs);
                return true;
            }
        }
    }
    return false;
}

static void cpu_sparc_disas_set_info(CPUState *cpu, disassemble_info *info)
{
    info->print_insn = print_insn_sparc;
#ifdef TARGET_SPARC64
    info->mach = bfd_mach_sparc_v9b;
#endif
}

static void
cpu_add_feat_as_prop(const char *typename, const char *name, const char *val)
{
    GlobalProperty *prop = g_new0(typeof(*prop), 1);
    prop->driver = typename;
    prop->property = g_strdup(name);
    prop->value = g_strdup(val);
    qdev_prop_register_global(prop);
}

/* Parse "+feature,-feature,feature=foo" CPU feature string */
static void sparc_cpu_parse_features(const char *typename, char *features,
                                     Error **errp)
{
    GList *l, *plus_features = NULL, *minus_features = NULL;
    char *featurestr; /* Single 'key=value" string being parsed */
    static bool cpu_globals_initialized;

    if (cpu_globals_initialized) {
        return;
    }
    cpu_globals_initialized = true;

    if (!features) {
        return;
    }

    for (featurestr = strtok(features, ",");
         featurestr;
         featurestr = strtok(NULL, ",")) {
        const char *name;
        const char *val = NULL;
        char *eq = NULL;

        /* Compatibility syntax: */
        if (featurestr[0] == '+') {
            plus_features = g_list_append(plus_features,
                                          g_strdup(featurestr + 1));
            continue;
        } else if (featurestr[0] == '-') {
            minus_features = g_list_append(minus_features,
                                           g_strdup(featurestr + 1));
            continue;
        }

        eq = strchr(featurestr, '=');
        name = featurestr;
        if (eq) {
            *eq++ = 0;
            val = eq;

            /*
             * Temporarily, only +feat/-feat will be supported
             * for boolean properties until we remove the
             * minus-overrides-plus semantics and just follow
             * the order options appear on the command-line.
             *
             * TODO: warn if user is relying on minus-override-plus semantics
             * TODO: remove minus-override-plus semantics after
             *       warning for a few releases
             */
            if (!strcasecmp(val, "on") ||
                !strcasecmp(val, "off") ||
                !strcasecmp(val, "true") ||
                !strcasecmp(val, "false")) {
                error_setg(errp, "Boolean properties in format %s=%s"
                                 " are not supported", name, val);
                return;
            }
        } else {
            error_setg(errp, "Unsupported property format: %s", name);
            return;
        }
        cpu_add_feat_as_prop(typename, name, val);
    }

    for (l = plus_features; l; l = l->next) {
        const char *name = l->data;
        cpu_add_feat_as_prop(typename, name, "on");
    }
    g_list_free_full(plus_features, g_free);

    for (l = minus_features; l; l = l->next) {
        const char *name = l->data;
        cpu_add_feat_as_prop(typename, name, "off");
    }
    g_list_free_full(minus_features, g_free);
}

void cpu_sparc_set_id(CPUSPARCState *env, unsigned int cpu)
{
#if !defined(TARGET_SPARC64)
    env->mxccregs[7] = ((cpu + 8) & 0xf) << 24;
#endif
}

static const sparc_def_t sparc_defs[] = {
#ifdef TARGET_SPARC64
    {
        .name = "Fujitsu Sparc64",
        .iu_version = ((0x04ULL << 48) | (0x02ULL << 32) | (0ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 4,
        .maxtl = 4,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Fujitsu Sparc64 III",
        .iu_version = ((0x04ULL << 48) | (0x03ULL << 32) | (0ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 5,
        .maxtl = 4,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Fujitsu Sparc64 IV",
        .iu_version = ((0x04ULL << 48) | (0x04ULL << 32) | (0ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Fujitsu Sparc64 V",
        .iu_version = ((0x04ULL << 48) | (0x05ULL << 32) | (0x51ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI UltraSparc I",
        .iu_version = ((0x17ULL << 48) | (0x10ULL << 32) | (0x40ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI UltraSparc II",
        .iu_version = ((0x17ULL << 48) | (0x11ULL << 32) | (0x20ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI UltraSparc IIi",
        .iu_version = ((0x17ULL << 48) | (0x12ULL << 32) | (0x91ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI UltraSparc IIe",
        .iu_version = ((0x17ULL << 48) | (0x13ULL << 32) | (0x14ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc III",
        .iu_version = ((0x3eULL << 48) | (0x14ULL << 32) | (0x34ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc III Cu",
        .iu_version = ((0x3eULL << 48) | (0x15ULL << 32) | (0x41ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_3,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc IIIi",
        .iu_version = ((0x3eULL << 48) | (0x16ULL << 32) | (0x34ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc IV",
        .iu_version = ((0x3eULL << 48) | (0x18ULL << 32) | (0x31ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_4,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc IV+",
        .iu_version = ((0x3eULL << 48) | (0x19ULL << 32) | (0x22ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES | CPU_FEATURE_CMT,
    },
    {
        .name = "Sun UltraSparc IIIi+",
        .iu_version = ((0x3eULL << 48) | (0x22ULL << 32) | (0ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_3,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Sun UltraSparc T1",
        /* defined in sparc_ifu_fdp.v and ctu.h */
        .iu_version = ((0x3eULL << 48) | (0x23ULL << 32) | (0x02ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_sun4v,
        .nwindows = 8,
        .maxtl = 6,
        .features = CPU_DEFAULT_FEATURES | CPU_FEATURE_HYPV | CPU_FEATURE_CMT
        | CPU_FEATURE_GL,
    },
    {
        .name = "Sun UltraSparc T2",
        /* defined in tlu_asi_ctl.v and n2_revid_cust.v */
        .iu_version = ((0x3eULL << 48) | (0x24ULL << 32) | (0x02ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_sun4v,
        .nwindows = 8,
        .maxtl = 6,
        .features = CPU_DEFAULT_FEATURES | CPU_FEATURE_HYPV | CPU_FEATURE_CMT
        | CPU_FEATURE_GL,
    },
    {
        .name = "NEC UltraSparc I",
        .iu_version = ((0x22ULL << 48) | (0x10ULL << 32) | (0x40ULL << 24)),
        .fpu_version = 0x00000000,
        .mmu_version = mmu_us_12,
        .nwindows = 8,
        .maxtl = 5,
        .features = CPU_DEFAULT_FEATURES,
    },
#else
    {
        .name = "Fujitsu MB86904",
        .iu_version = 0x04 << 24, /* Impl 0, ver 4 */
        .fpu_version = 4 << 17, /* FPU version 4 (Meiko) */
        .mmu_version = 0x04 << 24, /* Impl 0, ver 4 */
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0x00ffffc0,
        .mmu_cxr_mask = 0x000000ff,
        .mmu_sfsr_mask = 0x00016fff,
        .mmu_trcr_mask = 0x00ffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "Fujitsu MB86907",
        .iu_version = 0x05 << 24, /* Impl 0, ver 5 */
        .fpu_version = 4 << 17, /* FPU version 4 (Meiko) */
        .mmu_version = 0x05 << 24, /* Impl 0, ver 5 */
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x000000ff,
        .mmu_sfsr_mask = 0x00016fff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI MicroSparc I",
        .iu_version = 0x41000000,
        .fpu_version = 4 << 17,
        .mmu_version = 0x41000000,
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0x007ffff0,
        .mmu_cxr_mask = 0x0000003f,
        .mmu_sfsr_mask = 0x00016fff,
        .mmu_trcr_mask = 0x0000003f,
        .nwindows = 7,
        .features = CPU_FEATURE_FLOAT | CPU_FEATURE_SWAP | CPU_FEATURE_MUL |
        CPU_FEATURE_DIV | CPU_FEATURE_FLUSH | CPU_FEATURE_FSQRT |
        CPU_FEATURE_FMUL,
    },
    {
        .name = "TI MicroSparc II",
        .iu_version = 0x42000000,
        .fpu_version = 4 << 17,
        .mmu_version = 0x02000000,
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0x00ffffc0,
        .mmu_cxr_mask = 0x000000ff,
        .mmu_sfsr_mask = 0x00016fff,
        .mmu_trcr_mask = 0x00ffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI MicroSparc IIep",
        .iu_version = 0x42000000,
        .fpu_version = 4 << 17,
        .mmu_version = 0x04000000,
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0x00ffffc0,
        .mmu_cxr_mask = 0x000000ff,
        .mmu_sfsr_mask = 0x00016bff,
        .mmu_trcr_mask = 0x00ffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc 40", /* STP1020NPGA */
        .iu_version = 0x41000000, /* SuperSPARC 2.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x00000800, /* SuperSPARC 2.x, no MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc 50", /* STP1020PGA */
        .iu_version = 0x40000000, /* SuperSPARC 3.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x01000800, /* SuperSPARC 3.x, no MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc 51",
        .iu_version = 0x40000000, /* SuperSPARC 3.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x01000000, /* SuperSPARC 3.x, MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .mxcc_version = 0x00000104,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc 60", /* STP1020APGA */
        .iu_version = 0x40000000, /* SuperSPARC 3.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x01000800, /* SuperSPARC 3.x, no MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc 61",
        .iu_version = 0x44000000, /* SuperSPARC 3.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x01000000, /* SuperSPARC 3.x, MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .mxcc_version = 0x00000104,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "TI SuperSparc II",
        .iu_version = 0x40000000, /* SuperSPARC II 1.x */
        .fpu_version = 0 << 17,
        .mmu_version = 0x08000000, /* SuperSPARC II 1.x, MXCC */
        .mmu_bm = 0x00002000,
        .mmu_ctpr_mask = 0xffffffc0,
        .mmu_cxr_mask = 0x0000ffff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .mxcc_version = 0x00000104,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES,
    },
    {
        .name = "LEON2",
        .iu_version = 0xf2000000,
        .fpu_version = 4 << 17, /* FPU version 4 (Meiko) */
        .mmu_version = 0xf2000000,
        .mmu_bm = 0x00004000,
        .mmu_ctpr_mask = 0x007ffff0,
        .mmu_cxr_mask = 0x0000003f,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES | CPU_FEATURE_TA0_SHUTDOWN,
    },
    {
        .name = "LEON3",
        .iu_version = 0xf3000000,
        .fpu_version = 4 << 17, /* FPU version 4 (Meiko) */
        .mmu_version = 0xf3000000,
        .mmu_bm = 0x00000000,
        .mmu_ctpr_mask = 0xfffffffc,
        .mmu_cxr_mask = 0x000000ff,
        .mmu_sfsr_mask = 0xffffffff,
        .mmu_trcr_mask = 0xffffffff,
        .nwindows = 8,
        .features = CPU_DEFAULT_FEATURES | CPU_FEATURE_TA0_SHUTDOWN |
        CPU_FEATURE_ASR17 | CPU_FEATURE_CACHE_CTRL | CPU_FEATURE_POWERDOWN |
        CPU_FEATURE_CASA,
    },
#endif
};

static const char * const feature_name[] = {
    "float",
    "float128",
    "swap",
    "mul",
    "div",
    "flush",
    "fsqrt",
    "fmul",
    "vis1",
    "vis2",
    "fsmuld",
    "hypv",
    "cmt",
    "gl",
};

static void print_features(FILE *f, fprintf_function cpu_fprintf,
                           uint32_t features, const char *prefix)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(feature_name); i++) {
        if (feature_name[i] && (features & (1 << i))) {
            if (prefix) {
                (*cpu_fprintf)(f, "%s", prefix);
            }
            (*cpu_fprintf)(f, "%s ", feature_name[i]);
        }
    }
}

void sparc_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(sparc_defs); i++) {
        (*cpu_fprintf)(f, "Sparc %16s IU " TARGET_FMT_lx
                       " FPU %08x MMU %08x NWINS %d ",
                       sparc_defs[i].name,
                       sparc_defs[i].iu_version,
                       sparc_defs[i].fpu_version,
                       sparc_defs[i].mmu_version,
                       sparc_defs[i].nwindows);
        print_features(f, cpu_fprintf, CPU_DEFAULT_FEATURES &
                       ~sparc_defs[i].features, "-");
        print_features(f, cpu_fprintf, ~CPU_DEFAULT_FEATURES &
                       sparc_defs[i].features, "+");
        (*cpu_fprintf)(f, "\n");
    }
    (*cpu_fprintf)(f, "Default CPU feature flags (use '-' to remove): ");
    print_features(f, cpu_fprintf, CPU_DEFAULT_FEATURES, NULL);
    (*cpu_fprintf)(f, "\n");
    (*cpu_fprintf)(f, "Available CPU feature flags (use '+' to add): ");
    print_features(f, cpu_fprintf, ~CPU_DEFAULT_FEATURES, NULL);
    (*cpu_fprintf)(f, "\n");
    (*cpu_fprintf)(f, "Numerical features (use '=' to set): iu_version "
                   "fpu_version mmu_version nwindows\n");
}

static void cpu_print_cc(FILE *f, fprintf_function cpu_fprintf,
                         uint32_t cc)
{
    cpu_fprintf(f, "%c%c%c%c", cc & PSR_NEG ? 'N' : '-',
                cc & PSR_ZERO ? 'Z' : '-', cc & PSR_OVF ? 'V' : '-',
                cc & PSR_CARRY ? 'C' : '-');
}

#ifdef TARGET_SPARC64
#define REGS_PER_LINE 4
#else
#define REGS_PER_LINE 8
#endif

void sparc_cpu_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf,
                          int flags)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    int i, x;

    cpu_fprintf(f, "pc: " TARGET_FMT_lx "  npc: " TARGET_FMT_lx "\n", env->pc,
                env->npc);

    for (i = 0; i < 8; i++) {
        if (i % REGS_PER_LINE == 0) {
            cpu_fprintf(f, "%%g%d-%d:", i, i + REGS_PER_LINE - 1);
        }
        cpu_fprintf(f, " " TARGET_FMT_lx, env->gregs[i]);
        if (i % REGS_PER_LINE == REGS_PER_LINE - 1) {
            cpu_fprintf(f, "\n");
        }
    }
    for (x = 0; x < 3; x++) {
        for (i = 0; i < 8; i++) {
            if (i % REGS_PER_LINE == 0) {
                cpu_fprintf(f, "%%%c%d-%d: ",
                            x == 0 ? 'o' : (x == 1 ? 'l' : 'i'),
                            i, i + REGS_PER_LINE - 1);
            }
            cpu_fprintf(f, TARGET_FMT_lx " ", env->regwptr[i + x * 8]);
            if (i % REGS_PER_LINE == REGS_PER_LINE - 1) {
                cpu_fprintf(f, "\n");
            }
        }
    }

    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < TARGET_DPREGS; i++) {
            if ((i & 3) == 0) {
                cpu_fprintf(f, "%%f%02d: ", i * 2);
            }
            cpu_fprintf(f, " %016" PRIx64, env->fpr[i].ll);
            if ((i & 3) == 3) {
                cpu_fprintf(f, "\n");
            }
        }
    }

#ifdef TARGET_SPARC64
    cpu_fprintf(f, "pstate: %08x ccr: %02x (icc: ", env->pstate,
                (unsigned)cpu_get_ccr(env));
    cpu_print_cc(f, cpu_fprintf, cpu_get_ccr(env) << PSR_CARRY_SHIFT);
    cpu_fprintf(f, " xcc: ");
    cpu_print_cc(f, cpu_fprintf, cpu_get_ccr(env) << (PSR_CARRY_SHIFT - 4));
    cpu_fprintf(f, ") asi: %02x tl: %d pil: %x gl: %d\n", env->asi, env->tl,
                env->psrpil, env->gl);
    cpu_fprintf(f, "tbr: " TARGET_FMT_lx " hpstate: " TARGET_FMT_lx " htba: "
                TARGET_FMT_lx "\n", env->tbr, env->hpstate, env->htba);
    cpu_fprintf(f, "cansave: %d canrestore: %d otherwin: %d wstate: %d "
                "cleanwin: %d cwp: %d\n",
                env->cansave, env->canrestore, env->otherwin, env->wstate,
                env->cleanwin, env->nwindows - 1 - env->cwp);
    cpu_fprintf(f, "fsr: " TARGET_FMT_lx " y: " TARGET_FMT_lx " fprs: "
                TARGET_FMT_lx "\n", env->fsr, env->y, env->fprs);

#else
    cpu_fprintf(f, "psr: %08x (icc: ", cpu_get_psr(env));
    cpu_print_cc(f, cpu_fprintf, cpu_get_psr(env));
    cpu_fprintf(f, " SPE: %c%c%c) wim: %08x\n", env->psrs ? 'S' : '-',
                env->psrps ? 'P' : '-', env->psret ? 'E' : '-',
                env->wim);
    cpu_fprintf(f, "fsr: " TARGET_FMT_lx " y: " TARGET_FMT_lx "\n",
                env->fsr, env->y);
#endif
    cpu_fprintf(f, "\n");
}

static void sparc_cpu_set_pc(CPUState *cs, vaddr value)
{
    SPARCCPU *cpu = SPARC_CPU(cs);

    cpu->env.pc = value;
    cpu->env.npc = value + 4;
}

static void sparc_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    SPARCCPU *cpu = SPARC_CPU(cs);

    cpu->env.pc = tb->pc;
    cpu->env.npc = tb->cs_base;
}

static bool sparc_cpu_has_work(CPUState *cs)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;

    return (cs->interrupt_request & CPU_INTERRUPT_HARD) &&
           cpu_interrupts_enabled(env);
}

static char *sparc_cpu_type_name(const char *cpu_model)
{
    char *name = g_strdup_printf(SPARC_CPU_TYPE_NAME("%s"), cpu_model);
    char *s = name;

    /* SPARC cpu model names happen to have whitespaces,
     * as type names shouldn't have spaces replace them with '-'
     */
    while ((s = strchr(s, ' '))) {
        *s = '-';
    }

    return name;
}

static ObjectClass *sparc_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    typename = sparc_cpu_type_name(cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    return oc;
}

static void sparc_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    SPARCCPUClass *scc = SPARC_CPU_GET_CLASS(dev);
    Error *local_err = NULL;
    SPARCCPU *cpu = SPARC_CPU(dev);
    CPUSPARCState *env = &cpu->env;

#if defined(CONFIG_USER_ONLY)
    if ((env->def.features & CPU_FEATURE_FLOAT)) {
        env->def.features |= CPU_FEATURE_FLOAT128;
    }
#endif

    env->version = env->def.iu_version;
    env->fsr = env->def.fpu_version;
    env->nwindows = env->def.nwindows;
#if !defined(TARGET_SPARC64)
    env->mmuregs[0] |= env->def.mmu_version;
    cpu_sparc_set_id(env, 0);
    env->mxccregs[7] |= env->def.mxcc_version;
#else
    env->mmu_version = env->def.mmu_version;
    env->maxtl = env->def.maxtl;
    env->version |= env->def.maxtl << 8;
    env->version |= env->def.nwindows - 1;
#endif

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    qemu_init_vcpu(cs);

    scc->parent_realize(dev, errp);
}

static void sparc_cpu_initfn(Object *obj)
{
    CPUState *cs = CPU(obj);
    SPARCCPU *cpu = SPARC_CPU(obj);
    SPARCCPUClass *scc = SPARC_CPU_GET_CLASS(obj);
    CPUSPARCState *env = &cpu->env;

    cs->env_ptr = env;

    if (scc->cpu_def) {
        env->def = *scc->cpu_def;
    }
}

static void sparc_get_nwindows(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    SPARCCPU *cpu = SPARC_CPU(obj);
    int64_t value = cpu->env.def.nwindows;

    visit_type_int(v, name, &value, errp);
}

static void sparc_set_nwindows(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    const int64_t min = MIN_NWINDOWS;
    const int64_t max = MAX_NWINDOWS;
    SPARCCPU *cpu = SPARC_CPU(obj);
    Error *err = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    if (value < min || value > max) {
        error_setg(errp, "Property %s.%s doesn't take value %" PRId64
                   " (minimum: %" PRId64 ", maximum: %" PRId64 ")",
                   object_get_typename(obj), name ? name : "null",
                   value, min, max);
        return;
    }
    cpu->env.def.nwindows = value;
}

static PropertyInfo qdev_prop_nwindows = {
    .name  = "int",
    .get   = sparc_get_nwindows,
    .set   = sparc_set_nwindows,
};

static Property sparc_cpu_properties[] = {
    DEFINE_PROP_BIT("float",    SPARCCPU, env.def.features, 0, false),
    DEFINE_PROP_BIT("float128", SPARCCPU, env.def.features, 1, false),
    DEFINE_PROP_BIT("swap",     SPARCCPU, env.def.features, 2, false),
    DEFINE_PROP_BIT("mul",      SPARCCPU, env.def.features, 3, false),
    DEFINE_PROP_BIT("div",      SPARCCPU, env.def.features, 4, false),
    DEFINE_PROP_BIT("flush",    SPARCCPU, env.def.features, 5, false),
    DEFINE_PROP_BIT("fsqrt",    SPARCCPU, env.def.features, 6, false),
    DEFINE_PROP_BIT("fmul",     SPARCCPU, env.def.features, 7, false),
    DEFINE_PROP_BIT("vis1",     SPARCCPU, env.def.features, 8, false),
    DEFINE_PROP_BIT("vis2",     SPARCCPU, env.def.features, 9, false),
    DEFINE_PROP_BIT("fsmuld",   SPARCCPU, env.def.features, 10, false),
    DEFINE_PROP_BIT("hypv",     SPARCCPU, env.def.features, 11, false),
    DEFINE_PROP_BIT("cmt",      SPARCCPU, env.def.features, 12, false),
    DEFINE_PROP_BIT("gl",       SPARCCPU, env.def.features, 13, false),
    DEFINE_PROP_UNSIGNED("iu-version", SPARCCPU, env.def.iu_version, 0,
                         qdev_prop_uint64, target_ulong),
    DEFINE_PROP_UINT32("fpu-version", SPARCCPU, env.def.fpu_version, 0),
    DEFINE_PROP_UINT32("mmu-version", SPARCCPU, env.def.mmu_version, 0),
    { .name  = "nwindows", .info  = &qdev_prop_nwindows },
    DEFINE_PROP_END_OF_LIST()
};

static void sparc_cpu_class_init(ObjectClass *oc, void *data)
{
    SPARCCPUClass *scc = SPARC_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);

    device_class_set_parent_realize(dc, sparc_cpu_realizefn,
                                    &scc->parent_realize);
    dc->props = sparc_cpu_properties;

    scc->parent_reset = cc->reset;
    cc->reset = sparc_cpu_reset;

    cc->class_by_name = sparc_cpu_class_by_name;
    cc->parse_features = sparc_cpu_parse_features;
    cc->has_work = sparc_cpu_has_work;
    cc->do_interrupt = sparc_cpu_do_interrupt;
    cc->cpu_exec_interrupt = sparc_cpu_exec_interrupt;
    cc->dump_state = sparc_cpu_dump_state;
#if !defined(TARGET_SPARC64) && !defined(CONFIG_USER_ONLY)
    cc->memory_rw_debug = sparc_cpu_memory_rw_debug;
#endif
    cc->set_pc = sparc_cpu_set_pc;
    cc->synchronize_from_tb = sparc_cpu_synchronize_from_tb;
    cc->gdb_read_register = sparc_cpu_gdb_read_register;
    cc->gdb_write_register = sparc_cpu_gdb_write_register;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = sparc_cpu_handle_mmu_fault;
#else
    cc->do_unassigned_access = sparc_cpu_unassigned_access;
    cc->do_unaligned_access = sparc_cpu_do_unaligned_access;
    cc->get_phys_page_debug = sparc_cpu_get_phys_page_debug;
    cc->vmsd = &vmstate_sparc_cpu;
#endif
    cc->disas_set_info = cpu_sparc_disas_set_info;
    cc->tcg_initialize = sparc_tcg_init;

#if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
    cc->gdb_num_core_regs = 86;
#else
    cc->gdb_num_core_regs = 72;
#endif
}

static const TypeInfo sparc_cpu_type_info = {
    .name = TYPE_SPARC_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(SPARCCPU),
    .instance_init = sparc_cpu_initfn,
    .abstract = true,
    .class_size = sizeof(SPARCCPUClass),
    .class_init = sparc_cpu_class_init,
};

static void sparc_cpu_cpudef_class_init(ObjectClass *oc, void *data)
{
    SPARCCPUClass *scc = SPARC_CPU_CLASS(oc);
    scc->cpu_def = data;
}

static void sparc_register_cpudef_type(const struct sparc_def_t *def)
{
    char *typename = sparc_cpu_type_name(def->name);
    TypeInfo ti = {
        .name = typename,
        .parent = TYPE_SPARC_CPU,
        .class_init = sparc_cpu_cpudef_class_init,
        .class_data = (void *)def,
    };

    type_register(&ti);
    g_free(typename);
}

static void sparc_cpu_register_types(void)
{
    int i;

    type_register_static(&sparc_cpu_type_info);
    for (i = 0; i < ARRAY_SIZE(sparc_defs); i++) {
        sparc_register_cpudef_type(&sparc_defs[i]);
    }
}

type_init(sparc_cpu_register_types)

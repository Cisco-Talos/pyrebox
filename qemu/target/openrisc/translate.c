/*
 * OpenRISC translation
 *
 * Copyright (c) 2011-2012 Jia Liu <proljc@gmail.com>
 *                         Feng Gao <gf91597@gmail.com>
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "tcg-op.h"
#include "qemu-common.h"
#include "qemu/log.h"
#include "qemu/bitops.h"
#include "exec/cpu_ldst.h"
#include "exec/translator.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/gen-icount.h"

#include "trace-tcg.h"
#include "exec/log.h"

/* is_jmp field values */
#define DISAS_EXIT    DISAS_TARGET_0  /* force exit to main loop */
#define DISAS_JUMP    DISAS_TARGET_1  /* exit via jmp_pc/jmp_pc_imm */

typedef struct DisasContext {
    DisasContextBase base;
    uint32_t mem_idx;
    uint32_t tb_flags;
    uint32_t delayed_branch;

    /* If not -1, jmp_pc contains this value and so is a direct jump.  */
    target_ulong jmp_pc_imm;
} DisasContext;

static inline bool is_user(DisasContext *dc)
{
#ifdef CONFIG_USER_ONLY
    return true;
#else
    return !(dc->tb_flags & TB_FLAGS_SM);
#endif
}

/* Include the auto-generated decoder.  */
#include "decode.inc.c"

static TCGv cpu_sr;
static TCGv cpu_R[32];
static TCGv cpu_R0;
static TCGv cpu_pc;
static TCGv jmp_pc;            /* l.jr/l.jalr temp pc */
static TCGv cpu_ppc;
static TCGv cpu_sr_f;           /* bf/bnf, F flag taken */
static TCGv cpu_sr_cy;          /* carry (unsigned overflow) */
static TCGv cpu_sr_ov;          /* signed overflow */
static TCGv cpu_lock_addr;
static TCGv cpu_lock_value;
static TCGv_i32 fpcsr;
static TCGv_i64 cpu_mac;        /* MACHI:MACLO */
static TCGv_i32 cpu_dflag;

void openrisc_translate_init(void)
{
    static const char * const regnames[] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
    };
    int i;

    cpu_sr = tcg_global_mem_new(cpu_env,
                                offsetof(CPUOpenRISCState, sr), "sr");
    cpu_dflag = tcg_global_mem_new_i32(cpu_env,
                                       offsetof(CPUOpenRISCState, dflag),
                                       "dflag");
    cpu_pc = tcg_global_mem_new(cpu_env,
                                offsetof(CPUOpenRISCState, pc), "pc");
    cpu_ppc = tcg_global_mem_new(cpu_env,
                                 offsetof(CPUOpenRISCState, ppc), "ppc");
    jmp_pc = tcg_global_mem_new(cpu_env,
                                offsetof(CPUOpenRISCState, jmp_pc), "jmp_pc");
    cpu_sr_f = tcg_global_mem_new(cpu_env,
                                  offsetof(CPUOpenRISCState, sr_f), "sr_f");
    cpu_sr_cy = tcg_global_mem_new(cpu_env,
                                   offsetof(CPUOpenRISCState, sr_cy), "sr_cy");
    cpu_sr_ov = tcg_global_mem_new(cpu_env,
                                   offsetof(CPUOpenRISCState, sr_ov), "sr_ov");
    cpu_lock_addr = tcg_global_mem_new(cpu_env,
                                       offsetof(CPUOpenRISCState, lock_addr),
                                       "lock_addr");
    cpu_lock_value = tcg_global_mem_new(cpu_env,
                                        offsetof(CPUOpenRISCState, lock_value),
                                        "lock_value");
    fpcsr = tcg_global_mem_new_i32(cpu_env,
                                   offsetof(CPUOpenRISCState, fpcsr),
                                   "fpcsr");
    cpu_mac = tcg_global_mem_new_i64(cpu_env,
                                     offsetof(CPUOpenRISCState, mac),
                                     "mac");
    for (i = 0; i < 32; i++) {
        cpu_R[i] = tcg_global_mem_new(cpu_env,
                                      offsetof(CPUOpenRISCState,
                                               shadow_gpr[0][i]),
                                      regnames[i]);
    }
    cpu_R0 = cpu_R[0];
}

static void gen_exception(DisasContext *dc, unsigned int excp)
{
    TCGv_i32 tmp = tcg_const_i32(excp);
    gen_helper_exception(cpu_env, tmp);
    tcg_temp_free_i32(tmp);
}

static void gen_illegal_exception(DisasContext *dc)
{
    tcg_gen_movi_tl(cpu_pc, dc->base.pc_next);
    gen_exception(dc, EXCP_ILLEGAL);
    dc->base.is_jmp = DISAS_NORETURN;
}

/* not used yet, open it when we need or64.  */
/*#ifdef TARGET_OPENRISC64
static void check_ob64s(DisasContext *dc)
{
    if (!(dc->flags & CPUCFGR_OB64S)) {
        gen_illegal_exception(dc);
    }
}

static void check_of64s(DisasContext *dc)
{
    if (!(dc->flags & CPUCFGR_OF64S)) {
        gen_illegal_exception(dc);
    }
}

static void check_ov64s(DisasContext *dc)
{
    if (!(dc->flags & CPUCFGR_OV64S)) {
        gen_illegal_exception(dc);
    }
}
#endif*/

/* We're about to write to REG.  On the off-chance that the user is
   writing to R0, re-instate the architectural register.  */
#define check_r0_write(reg)             \
    do {                                \
        if (unlikely(reg == 0)) {       \
            cpu_R[0] = cpu_R0;          \
        }                               \
    } while (0)

static void gen_ove_cy(DisasContext *dc)
{
    if (dc->tb_flags & SR_OVE) {
        gen_helper_ove_cy(cpu_env);
    }
}

static void gen_ove_ov(DisasContext *dc)
{
    if (dc->tb_flags & SR_OVE) {
        gen_helper_ove_ov(cpu_env);
    }
}

static void gen_ove_cyov(DisasContext *dc)
{
    if (dc->tb_flags & SR_OVE) {
        gen_helper_ove_cyov(cpu_env);
    }
}

static void gen_add(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv t0 = tcg_const_tl(0);
    TCGv res = tcg_temp_new();

    tcg_gen_add2_tl(res, cpu_sr_cy, srca, t0, srcb, t0);
    tcg_gen_xor_tl(cpu_sr_ov, srca, srcb);
    tcg_gen_xor_tl(t0, res, srcb);
    tcg_gen_andc_tl(cpu_sr_ov, t0, cpu_sr_ov);
    tcg_temp_free(t0);

    tcg_gen_mov_tl(dest, res);
    tcg_temp_free(res);

    gen_ove_cyov(dc);
}

static void gen_addc(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv t0 = tcg_const_tl(0);
    TCGv res = tcg_temp_new();

    tcg_gen_add2_tl(res, cpu_sr_cy, srca, t0, cpu_sr_cy, t0);
    tcg_gen_add2_tl(res, cpu_sr_cy, res, cpu_sr_cy, srcb, t0);
    tcg_gen_xor_tl(cpu_sr_ov, srca, srcb);
    tcg_gen_xor_tl(t0, res, srcb);
    tcg_gen_andc_tl(cpu_sr_ov, t0, cpu_sr_ov);
    tcg_temp_free(t0);

    tcg_gen_mov_tl(dest, res);
    tcg_temp_free(res);

    gen_ove_cyov(dc);
}

static void gen_sub(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv res = tcg_temp_new();

    tcg_gen_sub_tl(res, srca, srcb);
    tcg_gen_xor_tl(cpu_sr_cy, srca, srcb);
    tcg_gen_xor_tl(cpu_sr_ov, res, srcb);
    tcg_gen_and_tl(cpu_sr_ov, cpu_sr_ov, cpu_sr_cy);
    tcg_gen_setcond_tl(TCG_COND_LTU, cpu_sr_cy, srca, srcb);

    tcg_gen_mov_tl(dest, res);
    tcg_temp_free(res);

    gen_ove_cyov(dc);
}

static void gen_mul(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv t0 = tcg_temp_new();

    tcg_gen_muls2_tl(dest, cpu_sr_ov, srca, srcb);
    tcg_gen_sari_tl(t0, dest, TARGET_LONG_BITS - 1);
    tcg_gen_setcond_tl(TCG_COND_NE, cpu_sr_ov, cpu_sr_ov, t0);
    tcg_temp_free(t0);

    tcg_gen_neg_tl(cpu_sr_ov, cpu_sr_ov);
    gen_ove_ov(dc);
}

static void gen_mulu(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    tcg_gen_muls2_tl(dest, cpu_sr_cy, srca, srcb);
    tcg_gen_setcondi_tl(TCG_COND_NE, cpu_sr_cy, cpu_sr_cy, 0);

    gen_ove_cy(dc);
}

static void gen_div(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv t0 = tcg_temp_new();

    tcg_gen_setcondi_tl(TCG_COND_EQ, cpu_sr_ov, srcb, 0);
    /* The result of divide-by-zero is undefined.
       Supress the host-side exception by dividing by 1.  */
    tcg_gen_or_tl(t0, srcb, cpu_sr_ov);
    tcg_gen_div_tl(dest, srca, t0);
    tcg_temp_free(t0);

    tcg_gen_neg_tl(cpu_sr_ov, cpu_sr_ov);
    gen_ove_ov(dc);
}

static void gen_divu(DisasContext *dc, TCGv dest, TCGv srca, TCGv srcb)
{
    TCGv t0 = tcg_temp_new();

    tcg_gen_setcondi_tl(TCG_COND_EQ, cpu_sr_cy, srcb, 0);
    /* The result of divide-by-zero is undefined.
       Supress the host-side exception by dividing by 1.  */
    tcg_gen_or_tl(t0, srcb, cpu_sr_cy);
    tcg_gen_divu_tl(dest, srca, t0);
    tcg_temp_free(t0);

    gen_ove_cy(dc);
}

static void gen_muld(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_ext_tl_i64(t1, srca);
    tcg_gen_ext_tl_i64(t2, srcb);
    if (TARGET_LONG_BITS == 32) {
        tcg_gen_mul_i64(cpu_mac, t1, t2);
        tcg_gen_movi_tl(cpu_sr_ov, 0);
    } else {
        TCGv_i64 high = tcg_temp_new_i64();

        tcg_gen_muls2_i64(cpu_mac, high, t1, t2);
        tcg_gen_sari_i64(t1, cpu_mac, 63);
        tcg_gen_setcond_i64(TCG_COND_NE, t1, t1, high);
        tcg_temp_free_i64(high);
        tcg_gen_trunc_i64_tl(cpu_sr_ov, t1);
        tcg_gen_neg_tl(cpu_sr_ov, cpu_sr_ov);

        gen_ove_ov(dc);
    }
    tcg_temp_free_i64(t1);
    tcg_temp_free_i64(t2);
}

static void gen_muldu(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_extu_tl_i64(t1, srca);
    tcg_gen_extu_tl_i64(t2, srcb);
    if (TARGET_LONG_BITS == 32) {
        tcg_gen_mul_i64(cpu_mac, t1, t2);
        tcg_gen_movi_tl(cpu_sr_cy, 0);
    } else {
        TCGv_i64 high = tcg_temp_new_i64();

        tcg_gen_mulu2_i64(cpu_mac, high, t1, t2);
        tcg_gen_setcondi_i64(TCG_COND_NE, high, high, 0);
        tcg_gen_trunc_i64_tl(cpu_sr_cy, high);
        tcg_temp_free_i64(high);

        gen_ove_cy(dc);
    }
    tcg_temp_free_i64(t1);
    tcg_temp_free_i64(t2);
}

static void gen_mac(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_ext_tl_i64(t1, srca);
    tcg_gen_ext_tl_i64(t2, srcb);
    tcg_gen_mul_i64(t1, t1, t2);

    /* Note that overflow is only computed during addition stage.  */
    tcg_gen_xor_i64(t2, cpu_mac, t1);
    tcg_gen_add_i64(cpu_mac, cpu_mac, t1);
    tcg_gen_xor_i64(t1, t1, cpu_mac);
    tcg_gen_andc_i64(t1, t1, t2);
    tcg_temp_free_i64(t2);

#if TARGET_LONG_BITS == 32
    tcg_gen_extrh_i64_i32(cpu_sr_ov, t1);
#else
    tcg_gen_mov_i64(cpu_sr_ov, t1);
#endif
    tcg_temp_free_i64(t1);

    gen_ove_ov(dc);
}

static void gen_macu(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_extu_tl_i64(t1, srca);
    tcg_gen_extu_tl_i64(t2, srcb);
    tcg_gen_mul_i64(t1, t1, t2);
    tcg_temp_free_i64(t2);

    /* Note that overflow is only computed during addition stage.  */
    tcg_gen_add_i64(cpu_mac, cpu_mac, t1);
    tcg_gen_setcond_i64(TCG_COND_LTU, t1, cpu_mac, t1);
    tcg_gen_trunc_i64_tl(cpu_sr_cy, t1);
    tcg_temp_free_i64(t1);

    gen_ove_cy(dc);
}

static void gen_msb(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_ext_tl_i64(t1, srca);
    tcg_gen_ext_tl_i64(t2, srcb);
    tcg_gen_mul_i64(t1, t1, t2);

    /* Note that overflow is only computed during subtraction stage.  */
    tcg_gen_xor_i64(t2, cpu_mac, t1);
    tcg_gen_sub_i64(cpu_mac, cpu_mac, t1);
    tcg_gen_xor_i64(t1, t1, cpu_mac);
    tcg_gen_and_i64(t1, t1, t2);
    tcg_temp_free_i64(t2);

#if TARGET_LONG_BITS == 32
    tcg_gen_extrh_i64_i32(cpu_sr_ov, t1);
#else
    tcg_gen_mov_i64(cpu_sr_ov, t1);
#endif
    tcg_temp_free_i64(t1);

    gen_ove_ov(dc);
}

static void gen_msbu(DisasContext *dc, TCGv srca, TCGv srcb)
{
    TCGv_i64 t1 = tcg_temp_new_i64();
    TCGv_i64 t2 = tcg_temp_new_i64();

    tcg_gen_extu_tl_i64(t1, srca);
    tcg_gen_extu_tl_i64(t2, srcb);
    tcg_gen_mul_i64(t1, t1, t2);

    /* Note that overflow is only computed during subtraction stage.  */
    tcg_gen_setcond_i64(TCG_COND_LTU, t2, cpu_mac, t1);
    tcg_gen_sub_i64(cpu_mac, cpu_mac, t1);
    tcg_gen_trunc_i64_tl(cpu_sr_cy, t2);
    tcg_temp_free_i64(t2);
    tcg_temp_free_i64(t1);

    gen_ove_cy(dc);
}

static bool trans_l_add(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_add(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_addc(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_addc(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sub(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_sub(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_and(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_and_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_or(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_or_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_xor(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_xor_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sll(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_shl_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_srl(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_shr_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sra(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_sar_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_ror(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    tcg_gen_rotr_tl(cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_exths(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_ext16s_tl(cpu_R[a->d], cpu_R[a->a]);
    return true;
}

static bool trans_l_extbs(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_ext8s_tl(cpu_R[a->d], cpu_R[a->a]);
    return true;
}

static bool trans_l_exthz(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_ext16u_tl(cpu_R[a->d], cpu_R[a->a]);
    return true;
}

static bool trans_l_extbz(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_ext8u_tl(cpu_R[a->d], cpu_R[a->a]);
    return true;
}

static bool trans_l_cmov(DisasContext *dc, arg_dab *a)
{
    TCGv zero;

    check_r0_write(a->d);
    zero = tcg_const_tl(0);
    tcg_gen_movcond_tl(TCG_COND_NE, cpu_R[a->d], cpu_sr_f, zero,
                       cpu_R[a->a], cpu_R[a->b]);
    tcg_temp_free(zero);
    return true;
}

static bool trans_l_ff1(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_ctzi_tl(cpu_R[a->d], cpu_R[a->a], -1);
    tcg_gen_addi_tl(cpu_R[a->d], cpu_R[a->d], 1);
    return true;
}

static bool trans_l_fl1(DisasContext *dc, arg_da *a)
{
    check_r0_write(a->d);
    tcg_gen_clzi_tl(cpu_R[a->d], cpu_R[a->a], TARGET_LONG_BITS);
    tcg_gen_subfi_tl(cpu_R[a->d], TARGET_LONG_BITS, cpu_R[a->d]);
    return true;
}

static bool trans_l_mul(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_mul(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_mulu(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_mulu(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_div(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_div(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_divu(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_divu(dc, cpu_R[a->d], cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_muld(DisasContext *dc, arg_ab *a)
{
    gen_muld(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_muldu(DisasContext *dc, arg_ab *a)
{
    gen_muldu(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_j(DisasContext *dc, arg_l_j *a)
{
    target_ulong tmp_pc = dc->base.pc_next + a->n * 4;

    tcg_gen_movi_tl(jmp_pc, tmp_pc);
    dc->jmp_pc_imm = tmp_pc;
    dc->delayed_branch = 2;
    return true;
}

static bool trans_l_jal(DisasContext *dc, arg_l_jal *a)
{
    target_ulong tmp_pc = dc->base.pc_next + a->n * 4;
    target_ulong ret_pc = dc->base.pc_next + 8;

    tcg_gen_movi_tl(cpu_R[9], ret_pc);
    /* Optimize jal being used to load the PC for PIC.  */
    if (tmp_pc != ret_pc) {
        tcg_gen_movi_tl(jmp_pc, tmp_pc);
        dc->jmp_pc_imm = tmp_pc;
        dc->delayed_branch = 2;
    }
    return true;
}

static void do_bf(DisasContext *dc, arg_l_bf *a, TCGCond cond)
{
    target_ulong tmp_pc = dc->base.pc_next + a->n * 4;
    TCGv t_next = tcg_const_tl(dc->base.pc_next + 8);
    TCGv t_true = tcg_const_tl(tmp_pc);
    TCGv t_zero = tcg_const_tl(0);

    tcg_gen_movcond_tl(cond, jmp_pc, cpu_sr_f, t_zero, t_true, t_next);

    tcg_temp_free(t_next);
    tcg_temp_free(t_true);
    tcg_temp_free(t_zero);
    dc->delayed_branch = 2;
}

static bool trans_l_bf(DisasContext *dc, arg_l_bf *a)
{
    do_bf(dc, a, TCG_COND_NE);
    return true;
}

static bool trans_l_bnf(DisasContext *dc, arg_l_bf *a)
{
    do_bf(dc, a, TCG_COND_EQ);
    return true;
}

static bool trans_l_jr(DisasContext *dc, arg_l_jr *a)
{
    tcg_gen_mov_tl(jmp_pc, cpu_R[a->b]);
    dc->delayed_branch = 2;
    return true;
}

static bool trans_l_jalr(DisasContext *dc, arg_l_jalr *a)
{
    tcg_gen_mov_tl(jmp_pc, cpu_R[a->b]);
    tcg_gen_movi_tl(cpu_R[9], dc->base.pc_next + 8);
    dc->delayed_branch = 2;
    return true;
}

static bool trans_l_lwa(DisasContext *dc, arg_load *a)
{
    TCGv ea;

    check_r0_write(a->d);
    ea = tcg_temp_new();
    tcg_gen_addi_tl(ea, cpu_R[a->a], a->i);
    tcg_gen_qemu_ld_tl(cpu_R[a->d], ea, dc->mem_idx, MO_TEUL);
    tcg_gen_mov_tl(cpu_lock_addr, ea);
    tcg_gen_mov_tl(cpu_lock_value, cpu_R[a->d]);
    tcg_temp_free(ea);
    return true;
}

static void do_load(DisasContext *dc, arg_load *a, TCGMemOp mop)
{
    TCGv ea;

    check_r0_write(a->d);
    ea = tcg_temp_new();
    tcg_gen_addi_tl(ea, cpu_R[a->a], a->i);
    tcg_gen_qemu_ld_tl(cpu_R[a->d], ea, dc->mem_idx, mop);
    tcg_temp_free(ea);
}

static bool trans_l_lwz(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_TEUL);
    return true;
}

static bool trans_l_lws(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_TESL);
    return true;
}

static bool trans_l_lbz(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_UB);
    return true;
}

static bool trans_l_lbs(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_SB);
    return true;
}

static bool trans_l_lhz(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_TEUW);
    return true;
}

static bool trans_l_lhs(DisasContext *dc, arg_load *a)
{
    do_load(dc, a, MO_TESW);
    return true;
}

static bool trans_l_swa(DisasContext *dc, arg_store *a)
{
    TCGv ea, val;
    TCGLabel *lab_fail, *lab_done;

    ea = tcg_temp_new();
    tcg_gen_addi_tl(ea, cpu_R[a->a], a->i);

    /* For TB_FLAGS_R0_0, the branch below invalidates the temporary assigned
       to cpu_R[0].  Since l.swa is quite often immediately followed by a
       branch, don't bother reallocating; finish the TB using the "real" R0.
       This also takes care of RB input across the branch.  */
    cpu_R[0] = cpu_R0;

    lab_fail = gen_new_label();
    lab_done = gen_new_label();
    tcg_gen_brcond_tl(TCG_COND_NE, ea, cpu_lock_addr, lab_fail);
    tcg_temp_free(ea);

    val = tcg_temp_new();
    tcg_gen_atomic_cmpxchg_tl(val, cpu_lock_addr, cpu_lock_value,
                              cpu_R[a->b], dc->mem_idx, MO_TEUL);
    tcg_gen_setcond_tl(TCG_COND_EQ, cpu_sr_f, val, cpu_lock_value);
    tcg_temp_free(val);

    tcg_gen_br(lab_done);

    gen_set_label(lab_fail);
    tcg_gen_movi_tl(cpu_sr_f, 0);

    gen_set_label(lab_done);
    tcg_gen_movi_tl(cpu_lock_addr, -1);
    return true;
}

static void do_store(DisasContext *dc, arg_store *a, TCGMemOp mop)
{
    TCGv t0 = tcg_temp_new();
    tcg_gen_addi_tl(t0, cpu_R[a->a], a->i);
    tcg_gen_qemu_st_tl(cpu_R[a->b], t0, dc->mem_idx, mop);
    tcg_temp_free(t0);
}

static bool trans_l_sw(DisasContext *dc, arg_store *a)
{
    do_store(dc, a, MO_TEUL);
    return true;
}

static bool trans_l_sb(DisasContext *dc, arg_store *a)
{
    do_store(dc, a, MO_UB);
    return true;
}

static bool trans_l_sh(DisasContext *dc, arg_store *a)
{
    do_store(dc, a, MO_TEUW);
    return true;
}

static bool trans_l_nop(DisasContext *dc, arg_l_nop *a)
{
    return true;
}

static bool trans_l_addi(DisasContext *dc, arg_rri *a)
{
    TCGv t0;

    check_r0_write(a->d);
    t0 = tcg_const_tl(a->i);
    gen_add(dc, cpu_R[a->d], cpu_R[a->a], t0);
    tcg_temp_free(t0);
    return true;
}

static bool trans_l_addic(DisasContext *dc, arg_rri *a)
{
    TCGv t0;

    check_r0_write(a->d);
    t0 = tcg_const_tl(a->i);
    gen_addc(dc, cpu_R[a->d], cpu_R[a->a], t0);
    tcg_temp_free(t0);
    return true;
}

static bool trans_l_muli(DisasContext *dc, arg_rri *a)
{
    TCGv t0;

    check_r0_write(a->d);
    t0 = tcg_const_tl(a->i);
    gen_mul(dc, cpu_R[a->d], cpu_R[a->a], t0);
    tcg_temp_free(t0);
    return true;
}

static bool trans_l_maci(DisasContext *dc, arg_l_maci *a)
{
    TCGv t0;

    t0 = tcg_const_tl(a->i);
    gen_mac(dc, cpu_R[a->a], t0);
    tcg_temp_free(t0);
    return true;
}

static bool trans_l_andi(DisasContext *dc, arg_rrk *a)
{
    check_r0_write(a->d);
    tcg_gen_andi_tl(cpu_R[a->d], cpu_R[a->a], a->k);
    return true;
}

static bool trans_l_ori(DisasContext *dc, arg_rrk *a)
{
    check_r0_write(a->d);
    tcg_gen_ori_tl(cpu_R[a->d], cpu_R[a->a], a->k);
    return true;
}

static bool trans_l_xori(DisasContext *dc, arg_rri *a)
{
    check_r0_write(a->d);
    tcg_gen_xori_tl(cpu_R[a->d], cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_mfspr(DisasContext *dc, arg_l_mfspr *a)
{
    check_r0_write(a->d);

    if (is_user(dc)) {
        gen_illegal_exception(dc);
    } else {
        TCGv spr = tcg_temp_new();
        tcg_gen_ori_tl(spr, cpu_R[a->a], a->k);
        gen_helper_mfspr(cpu_R[a->d], cpu_env, cpu_R[a->d], spr);
        tcg_temp_free(spr);
    }
    return true;
}

static bool trans_l_mtspr(DisasContext *dc, arg_l_mtspr *a)
{
    if (is_user(dc)) {
        gen_illegal_exception(dc);
    } else {
        TCGv spr;

        /* For SR, we will need to exit the TB to recognize the new
         * exception state.  For NPC, in theory this counts as a branch
         * (although the SPR only exists for use by an ICE).  Save all
         * of the cpu state first, allowing it to be overwritten.
         */
        if (dc->delayed_branch) {
            tcg_gen_mov_tl(cpu_pc, jmp_pc);
            tcg_gen_discard_tl(jmp_pc);
        } else {
            tcg_gen_movi_tl(cpu_pc, dc->base.pc_next + 4);
        }
        dc->base.is_jmp = DISAS_EXIT;

        spr = tcg_temp_new();
        tcg_gen_ori_tl(spr, cpu_R[a->a], a->k);
        gen_helper_mtspr(cpu_env, spr, cpu_R[a->b]);
        tcg_temp_free(spr);
    }
    return true;
}

static bool trans_l_mac(DisasContext *dc, arg_ab *a)
{
    gen_mac(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_msb(DisasContext *dc, arg_ab *a)
{
    gen_msb(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_macu(DisasContext *dc, arg_ab *a)
{
    gen_macu(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_msbu(DisasContext *dc, arg_ab *a)
{
    gen_msbu(dc, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_slli(DisasContext *dc, arg_dal *a)
{
    check_r0_write(a->d);
    tcg_gen_shli_tl(cpu_R[a->d], cpu_R[a->a], a->l & (TARGET_LONG_BITS - 1));
    return true;
}

static bool trans_l_srli(DisasContext *dc, arg_dal *a)
{
    check_r0_write(a->d);
    tcg_gen_shri_tl(cpu_R[a->d], cpu_R[a->a], a->l & (TARGET_LONG_BITS - 1));
    return true;
}

static bool trans_l_srai(DisasContext *dc, arg_dal *a)
{
    check_r0_write(a->d);
    tcg_gen_sari_tl(cpu_R[a->d], cpu_R[a->a], a->l & (TARGET_LONG_BITS - 1));
    return true;
}

static bool trans_l_rori(DisasContext *dc, arg_dal *a)
{
    check_r0_write(a->d);
    tcg_gen_rotri_tl(cpu_R[a->d], cpu_R[a->a], a->l & (TARGET_LONG_BITS - 1));
    return true;
}

static bool trans_l_movhi(DisasContext *dc, arg_l_movhi *a)
{
    check_r0_write(a->d);
    tcg_gen_movi_tl(cpu_R[a->d], a->k << 16);
    return true;
}

static bool trans_l_macrc(DisasContext *dc, arg_l_macrc *a)
{
    check_r0_write(a->d);
    tcg_gen_trunc_i64_tl(cpu_R[a->d], cpu_mac);
    tcg_gen_movi_i64(cpu_mac, 0);
    return true;
}

static bool trans_l_sfeq(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_EQ, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfne(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_NE, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfgtu(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_GTU, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfgeu(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_GEU, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfltu(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_LTU, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfleu(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_LEU, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfgts(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_GT, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfges(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_GE, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sflts(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_LT, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfles(DisasContext *dc, arg_ab *a)
{
    tcg_gen_setcond_tl(TCG_COND_LE, cpu_sr_f, cpu_R[a->a], cpu_R[a->b]);
    return true;
}

static bool trans_l_sfeqi(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_EQ, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfnei(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_NE, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfgtui(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_GTU, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfgeui(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_GEU, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfltui(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_LTU, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfleui(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_LEU, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfgtsi(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_GT, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfgesi(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_GE, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sfltsi(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_LT, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sflesi(DisasContext *dc, arg_ai *a)
{
    tcg_gen_setcondi_tl(TCG_COND_LE, cpu_sr_f, cpu_R[a->a], a->i);
    return true;
}

static bool trans_l_sys(DisasContext *dc, arg_l_sys *a)
{
    tcg_gen_movi_tl(cpu_pc, dc->base.pc_next);
    gen_exception(dc, EXCP_SYSCALL);
    dc->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_l_trap(DisasContext *dc, arg_l_trap *a)
{
    tcg_gen_movi_tl(cpu_pc, dc->base.pc_next);
    gen_exception(dc, EXCP_TRAP);
    dc->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_l_msync(DisasContext *dc, arg_l_msync *a)
{
    tcg_gen_mb(TCG_MO_ALL);
    return true;
}

static bool trans_l_psync(DisasContext *dc, arg_l_psync *a)
{
    return true;
}

static bool trans_l_csync(DisasContext *dc, arg_l_csync *a)
{
    return true;
}

static bool trans_l_rfe(DisasContext *dc, arg_l_rfe *a)
{
    if (is_user(dc)) {
        gen_illegal_exception(dc);
    } else {
        gen_helper_rfe(cpu_env);
        dc->base.is_jmp = DISAS_EXIT;
    }
    return true;
}

static void do_fp2(DisasContext *dc, arg_da *a,
                   void (*fn)(TCGv, TCGv_env, TCGv))
{
    check_r0_write(a->d);
    fn(cpu_R[a->d], cpu_env, cpu_R[a->a]);
    gen_helper_update_fpcsr(cpu_env);
}

static void do_fp3(DisasContext *dc, arg_dab *a,
                   void (*fn)(TCGv, TCGv_env, TCGv, TCGv))
{
    check_r0_write(a->d);
    fn(cpu_R[a->d], cpu_env, cpu_R[a->a], cpu_R[a->b]);
    gen_helper_update_fpcsr(cpu_env);
}

static void do_fpcmp(DisasContext *dc, arg_ab *a,
                     void (*fn)(TCGv, TCGv_env, TCGv, TCGv),
                     bool inv, bool swap)
{
    if (swap) {
        fn(cpu_sr_f, cpu_env, cpu_R[a->b], cpu_R[a->a]);
    } else {
        fn(cpu_sr_f, cpu_env, cpu_R[a->a], cpu_R[a->b]);
    }
    if (inv) {
        tcg_gen_xori_tl(cpu_sr_f, cpu_sr_f, 1);
    }
    gen_helper_update_fpcsr(cpu_env);
}

static bool trans_lf_add_s(DisasContext *dc, arg_dab *a)
{
    do_fp3(dc, a, gen_helper_float_add_s);
    return true;
}

static bool trans_lf_sub_s(DisasContext *dc, arg_dab *a)
{
    do_fp3(dc, a, gen_helper_float_sub_s);
    return true;
}

static bool trans_lf_mul_s(DisasContext *dc, arg_dab *a)
{
    do_fp3(dc, a, gen_helper_float_mul_s);
    return true;
}

static bool trans_lf_div_s(DisasContext *dc, arg_dab *a)
{
    do_fp3(dc, a, gen_helper_float_div_s);
    return true;
}

static bool trans_lf_rem_s(DisasContext *dc, arg_dab *a)
{
    do_fp3(dc, a, gen_helper_float_rem_s);
    return true;
}

static bool trans_lf_itof_s(DisasContext *dc, arg_da *a)
{
    do_fp2(dc, a, gen_helper_itofs);
    return true;
}

static bool trans_lf_ftoi_s(DisasContext *dc, arg_da *a)
{
    do_fp2(dc, a, gen_helper_ftois);
    return true;
}

static bool trans_lf_madd_s(DisasContext *dc, arg_dab *a)
{
    check_r0_write(a->d);
    gen_helper_float_madd_s(cpu_R[a->d], cpu_env, cpu_R[a->d],
                            cpu_R[a->a], cpu_R[a->b]);
    gen_helper_update_fpcsr(cpu_env);
    return true;
}

static bool trans_lf_sfeq_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_eq_s, false, false);
    return true;
}

static bool trans_lf_sfne_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_eq_s, true, false);
    return true;
}

static bool trans_lf_sfgt_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_lt_s, false, true);
    return true;
}

static bool trans_lf_sfge_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_le_s, false, true);
    return true;
}

static bool trans_lf_sflt_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_lt_s, false, false);
    return true;
}

static bool trans_lf_sfle_s(DisasContext *dc, arg_ab *a)
{
    do_fpcmp(dc, a, gen_helper_float_le_s, false, false);
    return true;
}

static void openrisc_tr_init_disas_context(DisasContextBase *dcb, CPUState *cs)
{
    DisasContext *dc = container_of(dcb, DisasContext, base);
    CPUOpenRISCState *env = cs->env_ptr;
    int bound;

    dc->mem_idx = cpu_mmu_index(env, false);
    dc->tb_flags = dc->base.tb->flags;
    dc->delayed_branch = (dc->tb_flags & TB_FLAGS_DFLAG) != 0;
    dc->jmp_pc_imm = -1;

    bound = -(dc->base.pc_first | TARGET_PAGE_MASK) / 4;
    dc->base.max_insns = MIN(dc->base.max_insns, bound);
}

static void openrisc_tr_tb_start(DisasContextBase *db, CPUState *cs)
{
    DisasContext *dc = container_of(db, DisasContext, base);

    /* Allow the TCG optimizer to see that R0 == 0,
       when it's true, which is the common case.  */
    if (dc->tb_flags & TB_FLAGS_R0_0) {
        cpu_R[0] = tcg_const_tl(0);
    } else {
        cpu_R[0] = cpu_R0;
    }
}

static void openrisc_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(dc->base.pc_next, (dc->delayed_branch ? 1 : 0)
                       | (dc->base.num_insns > 1 ? 2 : 0));
}

static bool openrisc_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cs,
                                         const CPUBreakpoint *bp)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    tcg_gen_movi_tl(cpu_pc, dc->base.pc_next);
    gen_exception(dc, EXCP_DEBUG);
    dc->base.is_jmp = DISAS_NORETURN;
    /* The address covered by the breakpoint must be included in
       [tb->pc, tb->pc + tb->size) in order to for it to be
       properly cleared -- thus we increment the PC here so that
       the logic setting tb->size below does the right thing.  */
    dc->base.pc_next += 4;
    return true;
}

static void openrisc_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    OpenRISCCPU *cpu = OPENRISC_CPU(cs);
    uint32_t insn = cpu_ldl_code(&cpu->env, dc->base.pc_next);

    if (!decode(dc, insn)) {
        gen_illegal_exception(dc);
    }
    dc->base.pc_next += 4;

    /* When exiting the delay slot normally, exit via jmp_pc.
     * For DISAS_NORETURN, we have raised an exception and already exited.
     * For DISAS_EXIT, we found l.rfe in a delay slot.  There's nothing
     * in the manual saying this is illegal, but it surely it should.
     * At least or1ksim overrides pcnext and ignores the branch.
     */
    if (dc->delayed_branch
        && --dc->delayed_branch == 0
        && dc->base.is_jmp == DISAS_NEXT) {
        dc->base.is_jmp = DISAS_JUMP;
    }
}

static void openrisc_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    target_ulong jmp_dest;

    /* If we have already exited the TB, nothing following has effect.  */
    if (dc->base.is_jmp == DISAS_NORETURN) {
        return;
    }

    /* Adjust the delayed branch state for the next TB.  */
    if ((dc->tb_flags & TB_FLAGS_DFLAG ? 1 : 0) != (dc->delayed_branch != 0)) {
        tcg_gen_movi_i32(cpu_dflag, dc->delayed_branch != 0);
    }

    /* For DISAS_TOO_MANY, jump to the next insn.  */
    jmp_dest = dc->base.pc_next;
    tcg_gen_movi_tl(cpu_ppc, jmp_dest - 4);

    switch (dc->base.is_jmp) {
    case DISAS_JUMP:
        jmp_dest = dc->jmp_pc_imm;
        if (jmp_dest == -1) {
            /* The jump destination is indirect/computed; use jmp_pc.  */
            tcg_gen_mov_tl(cpu_pc, jmp_pc);
            tcg_gen_discard_tl(jmp_pc);
            if (unlikely(dc->base.singlestep_enabled)) {
                gen_exception(dc, EXCP_DEBUG);
            } else {
                tcg_gen_lookup_and_goto_ptr();
            }
            break;
        }
        /* The jump destination is direct; use jmp_pc_imm.
           However, we will have stored into jmp_pc as well;
           we know now that it wasn't needed.  */
        tcg_gen_discard_tl(jmp_pc);
        /* fallthru */

    case DISAS_TOO_MANY:
        if (unlikely(dc->base.singlestep_enabled)) {
            tcg_gen_movi_tl(cpu_pc, jmp_dest);
            gen_exception(dc, EXCP_DEBUG);
        } else if ((dc->base.pc_first ^ jmp_dest) & TARGET_PAGE_MASK) {
            tcg_gen_movi_tl(cpu_pc, jmp_dest);
            tcg_gen_lookup_and_goto_ptr();
        } else {
            tcg_gen_goto_tb(0);
            tcg_gen_movi_tl(cpu_pc, jmp_dest);
            tcg_gen_exit_tb(dc->base.tb, 0);
        }
        break;

    case DISAS_EXIT:
        if (unlikely(dc->base.singlestep_enabled)) {
            gen_exception(dc, EXCP_DEBUG);
        } else {
            tcg_gen_exit_tb(NULL, 0);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void openrisc_tr_disas_log(const DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *s = container_of(dcbase, DisasContext, base);

    qemu_log("IN: %s\n", lookup_symbol(s->base.pc_first));
    log_target_disas(cs, s->base.pc_first, s->base.tb->size);
}

static const TranslatorOps openrisc_tr_ops = {
    .init_disas_context = openrisc_tr_init_disas_context,
    .tb_start           = openrisc_tr_tb_start,
    .insn_start         = openrisc_tr_insn_start,
    .breakpoint_check   = openrisc_tr_breakpoint_check,
    .translate_insn     = openrisc_tr_translate_insn,
    .tb_stop            = openrisc_tr_tb_stop,
    .disas_log          = openrisc_tr_disas_log,
};

void gen_intermediate_code(CPUState *cs, struct TranslationBlock *tb)
{
    DisasContext ctx;

    translator_loop(&openrisc_tr_ops, &ctx.base, cs, tb);
}

void openrisc_cpu_dump_state(CPUState *cs, FILE *f,
                             fprintf_function cpu_fprintf,
                             int flags)
{
    OpenRISCCPU *cpu = OPENRISC_CPU(cs);
    CPUOpenRISCState *env = &cpu->env;
    int i;

    cpu_fprintf(f, "PC=%08x\n", env->pc);
    for (i = 0; i < 32; ++i) {
        cpu_fprintf(f, "R%02d=%08x%c", i, cpu_get_gpr(env, i),
                    (i % 4) == 3 ? '\n' : ' ');
    }
}

void restore_state_to_opc(CPUOpenRISCState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
    env->dflag = data[1] & 1;
    if (data[1] & 2) {
        env->ppc = env->pc - 4;
    }
}

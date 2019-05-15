/*
 * S390x DIAG instruction helper functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "exec/address-spaces.h"
#include "hw/watchdog/wdt_diag288.h"
#include "sysemu/cpus.h"
#include "hw/s390x/ipl.h"
#include "hw/s390x/s390-virtio-ccw.h"

int handle_diag_288(CPUS390XState *env, uint64_t r1, uint64_t r3)
{
    uint64_t func = env->regs[r1];
    uint64_t timeout = env->regs[r1 + 1];
    uint64_t action = env->regs[r3];
    Object *obj;
    DIAG288State *diag288;
    DIAG288Class *diag288_class;

    if (r1 % 2 || action != 0) {
        return -1;
    }

    /* Timeout must be more than 15 seconds except for timer deletion */
    if (func != WDT_DIAG288_CANCEL && timeout < 15) {
        return -1;
    }

    obj = object_resolve_path_type("", TYPE_WDT_DIAG288, NULL);
    if (!obj) {
        return -1;
    }

    diag288 = DIAG288(obj);
    diag288_class = DIAG288_GET_CLASS(diag288);
    return diag288_class->handle_timer(diag288, func, timeout);
}

#define DIAG_308_RC_OK              0x0001
#define DIAG_308_RC_NO_CONF         0x0102
#define DIAG_308_RC_INVALID         0x0402

void handle_diag_308(CPUS390XState *env, uint64_t r1, uint64_t r3, uintptr_t ra)
{
    CPUState *cs = CPU(s390_env_get_cpu(env));
    uint64_t addr =  env->regs[r1];
    uint64_t subcode = env->regs[r3];
    IplParameterBlock *iplb;

    if (env->psw.mask & PSW_MASK_PSTATE) {
        s390_program_interrupt(env, PGM_PRIVILEGED, ILEN_AUTO, ra);
        return;
    }

    if ((subcode & ~0x0ffffULL) || (subcode > 6)) {
        s390_program_interrupt(env, PGM_SPECIFICATION, ILEN_AUTO, ra);
        return;
    }

    switch (subcode) {
    case 0:
        s390_ipl_reset_request(cs, S390_RESET_MODIFIED_CLEAR);
        break;
    case 1:
        s390_ipl_reset_request(cs, S390_RESET_LOAD_NORMAL);
        break;
    case 3:
        s390_ipl_reset_request(cs, S390_RESET_REIPL);
        break;
    case 5:
        if ((r1 & 1) || (addr & 0x0fffULL)) {
            s390_program_interrupt(env, PGM_SPECIFICATION, ILEN_AUTO, ra);
            return;
        }
        if (!address_space_access_valid(&address_space_memory, addr,
                                        sizeof(IplParameterBlock), false,
                                        MEMTXATTRS_UNSPECIFIED)) {
            s390_program_interrupt(env, PGM_ADDRESSING, ILEN_AUTO, ra);
            return;
        }
        iplb = g_new0(IplParameterBlock, 1);
        cpu_physical_memory_read(addr, iplb, sizeof(iplb->len));
        if (!iplb_valid_len(iplb)) {
            env->regs[r1 + 1] = DIAG_308_RC_INVALID;
            goto out;
        }

        cpu_physical_memory_read(addr, iplb, be32_to_cpu(iplb->len));

        if (!iplb_valid_ccw(iplb) && !iplb_valid_fcp(iplb)) {
            env->regs[r1 + 1] = DIAG_308_RC_INVALID;
            goto out;
        }

        s390_ipl_update_diag308(iplb);
        env->regs[r1 + 1] = DIAG_308_RC_OK;
out:
        g_free(iplb);
        return;
    case 6:
        if ((r1 & 1) || (addr & 0x0fffULL)) {
            s390_program_interrupt(env, PGM_SPECIFICATION, ILEN_AUTO, ra);
            return;
        }
        if (!address_space_access_valid(&address_space_memory, addr,
                                        sizeof(IplParameterBlock), true,
                                        MEMTXATTRS_UNSPECIFIED)) {
            s390_program_interrupt(env, PGM_ADDRESSING, ILEN_AUTO, ra);
            return;
        }
        iplb = s390_ipl_get_iplb();
        if (iplb) {
            cpu_physical_memory_write(addr, iplb, be32_to_cpu(iplb->len));
            env->regs[r1 + 1] = DIAG_308_RC_OK;
        } else {
            env->regs[r1 + 1] = DIAG_308_RC_NO_CONF;
        }
        return;
    default:
        s390_program_interrupt(env, PGM_SPECIFICATION, ILEN_AUTO, ra);
        break;
    }
}

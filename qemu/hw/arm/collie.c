/*
 * SA-1110-based Sharp Zaurus SL-5500 platform.
 *
 * Copyright (C) 2011 Dmitry Eremin-Solenikov
 *
 * This code is licensed under GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/boards.h"
#include "strongarm.h"
#include "hw/arm/arm.h"
#include "hw/block/flash.h"
#include "exec/address-spaces.h"
#include "cpu.h"

static struct arm_boot_info collie_binfo = {
    .loader_start = SA_SDCS0,
    .ram_size = 0x20000000,
};

static void collie_init(MachineState *machine)
{
    const char *kernel_filename = machine->kernel_filename;
    const char *kernel_cmdline = machine->kernel_cmdline;
    const char *initrd_filename = machine->initrd_filename;
    StrongARMState *s;
    DriveInfo *dinfo;
    MemoryRegion *sysmem = get_system_memory();

    s = sa1110_init(sysmem, collie_binfo.ram_size, machine->cpu_type);

    dinfo = drive_get(IF_PFLASH, 0, 0);
    pflash_cfi01_register(SA_CS0, "collie.fl1", 0x02000000,
                    dinfo ? blk_by_legacy_dinfo(dinfo) : NULL,
                    64 * KiB, 4, 0x00, 0x00, 0x00, 0x00, 0);

    dinfo = drive_get(IF_PFLASH, 0, 1);
    pflash_cfi01_register(SA_CS1, "collie.fl2", 0x02000000,
                    dinfo ? blk_by_legacy_dinfo(dinfo) : NULL,
                    64 * KiB, 4, 0x00, 0x00, 0x00, 0x00, 0);

    sysbus_create_simple("scoop", 0x40800000, NULL);

    collie_binfo.kernel_filename = kernel_filename;
    collie_binfo.kernel_cmdline = kernel_cmdline;
    collie_binfo.initrd_filename = initrd_filename;
    collie_binfo.board_id = 0x208;
    arm_load_kernel(s->cpu, &collie_binfo);
}

static void collie_machine_init(MachineClass *mc)
{
    mc->desc = "Sharp SL-5500 (Collie) PDA (SA-1110)";
    mc->init = collie_init;
    mc->ignore_memory_transaction_failures = true;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("sa1110");
}

DEFINE_MACHINE("collie", collie_machine_init)

/*
 * Empty machine
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "hw/hw.h"
#include "hw/boards.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"
#include "qom/cpu.h"

static void machine_none_init(MachineState *mch)
{
    CPUState *cpu = NULL;

    /* Initialize CPU (if user asked for it) */
    if (mch->cpu_type) {
        cpu = cpu_create(mch->cpu_type);
        if (!cpu) {
            error_report("Unable to initialize CPU");
            exit(1);
        }
    }

    /* RAM at address zero */
    if (mch->ram_size) {
        MemoryRegion *ram = g_new(MemoryRegion, 1);

        memory_region_allocate_system_memory(ram, NULL, "ram", mch->ram_size);
        memory_region_add_subregion(get_system_memory(), 0, ram);
    }

    if (mch->kernel_filename) {
        error_report("The -kernel parameter is not supported "
                     "(use the generic 'loader' device instead).");
        exit(1);
    }
}

static void machine_none_machine_init(MachineClass *mc)
{
    mc->desc = "empty machine";
    mc->init = machine_none_init;
    mc->max_cpus = 1;
    mc->default_ram_size = 0;
}

DEFINE_MACHINE("none", machine_none_machine_init)

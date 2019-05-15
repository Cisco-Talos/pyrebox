/*
 *  QEMU model for the Milkymist board.
 *
 *  Copyright (c) 2010 Michael Walle <michael@walle.cc>
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
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/sysbus.h"
#include "hw/hw.h"
#include "hw/block/flash.h"
#include "sysemu/sysemu.h"
#include "sysemu/qtest.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "elf.h"
#include "milkymist-hw.h"
#include "hw/display/milkymist_tmu2.h"
#include "lm32.h"
#include "exec/address-spaces.h"

#define BIOS_FILENAME    "mmone-bios.bin"
#define BIOS_OFFSET      0x00860000
#define BIOS_SIZE        (512 * KiB)
#define KERNEL_LOAD_ADDR 0x40000000

typedef struct {
    LM32CPU *cpu;
    hwaddr bootstrap_pc;
    hwaddr flash_base;
    hwaddr initrd_base;
    size_t initrd_size;
    hwaddr cmdline_base;
} ResetInfo;

static void cpu_irq_handler(void *opaque, int irq, int level)
{
    LM32CPU *cpu = opaque;
    CPUState *cs = CPU(cpu);

    if (level) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

static void main_cpu_reset(void *opaque)
{
    ResetInfo *reset_info = opaque;
    CPULM32State *env = &reset_info->cpu->env;

    cpu_reset(CPU(reset_info->cpu));

    /* init defaults */
    env->pc = reset_info->bootstrap_pc;
    env->regs[R_R1] = reset_info->cmdline_base;
    env->regs[R_R2] = reset_info->initrd_base;
    env->regs[R_R3] = reset_info->initrd_base + reset_info->initrd_size;
    env->eba = reset_info->flash_base;
    env->deba = reset_info->flash_base;
}

static void
milkymist_init(MachineState *machine)
{
    const char *kernel_filename = machine->kernel_filename;
    const char *kernel_cmdline = machine->kernel_cmdline;
    const char *initrd_filename = machine->initrd_filename;
    LM32CPU *cpu;
    CPULM32State *env;
    int kernel_size;
    DriveInfo *dinfo;
    MemoryRegion *address_space_mem = get_system_memory();
    MemoryRegion *phys_sdram = g_new(MemoryRegion, 1);
    qemu_irq irq[32];
    int i;
    char *bios_filename;
    ResetInfo *reset_info;

    /* memory map */
    hwaddr flash_base   = 0x00000000;
    size_t flash_sector_size        = 128 * KiB;
    size_t flash_size               = 32 * MiB;
    hwaddr sdram_base   = 0x40000000;
    size_t sdram_size               = 128 * MiB;

    hwaddr initrd_base  = sdram_base + 0x1002000;
    hwaddr cmdline_base = sdram_base + 0x1000000;
    size_t initrd_max = sdram_size - 0x1002000;

    reset_info = g_malloc0(sizeof(ResetInfo));

    cpu = LM32_CPU(cpu_create(machine->cpu_type));

    env = &cpu->env;
    reset_info->cpu = cpu;

    cpu_lm32_set_phys_msb_ignore(env, 1);

    memory_region_allocate_system_memory(phys_sdram, NULL, "milkymist.sdram",
                                         sdram_size);
    memory_region_add_subregion(address_space_mem, sdram_base, phys_sdram);

    dinfo = drive_get(IF_PFLASH, 0, 0);
    /* Numonyx JS28F256J3F105 */
    pflash_cfi01_register(flash_base, "milkymist.flash", flash_size,
                          dinfo ? blk_by_legacy_dinfo(dinfo) : NULL,
                          flash_sector_size, 2, 0x00, 0x89, 0x00, 0x1d, 1);

    /* create irq lines */
    env->pic_state = lm32_pic_init(qemu_allocate_irq(cpu_irq_handler, cpu, 0));
    for (i = 0; i < 32; i++) {
        irq[i] = qdev_get_gpio_in(env->pic_state, i);
    }

    /* load bios rom */
    if (bios_name == NULL) {
        bios_name = BIOS_FILENAME;
    }
    bios_filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);

    if (bios_filename) {
        if (load_image_targphys(bios_filename, BIOS_OFFSET, BIOS_SIZE) < 0) {
            error_report("could not load bios '%s'", bios_filename);
            exit(1);
        }
    }

    reset_info->bootstrap_pc = BIOS_OFFSET;

    /* if no kernel is given no valid bios rom is a fatal error */
    if (!kernel_filename && !dinfo && !bios_filename && !qtest_enabled()) {
        error_report("could not load Milkymist One bios '%s'", bios_name);
        exit(1);
    }
    g_free(bios_filename);

    milkymist_uart_create(0x60000000, irq[0], serial_hd(0));
    milkymist_sysctl_create(0x60001000, irq[1], irq[2], irq[3],
            80000000, 0x10014d31, 0x0000041f, 0x00000001);
    milkymist_hpdmc_create(0x60002000);
    milkymist_vgafb_create(0x60003000, 0x40000000, 0x0fffffff);
    milkymist_memcard_create(0x60004000);
    milkymist_ac97_create(0x60005000, irq[4], irq[5], irq[6], irq[7]);
    milkymist_pfpu_create(0x60006000, irq[8]);
    if (machine->enable_graphics) {
        milkymist_tmu2_create(0x60007000, irq[9]);
    }
    milkymist_minimac2_create(0x60008000, 0x30000000, irq[10], irq[11]);
    milkymist_softusb_create(0x6000f000, irq[15],
            0x20000000, 0x1000, 0x20020000, 0x2000);

    /* make sure juart isn't the first chardev */
    env->juart_state = lm32_juart_init(serial_hd(1));

    if (kernel_filename) {
        uint64_t entry;

        /* Boots a kernel elf binary.  */
        kernel_size = load_elf(kernel_filename, NULL, NULL, NULL,
                               &entry, NULL, NULL,
                               1, EM_LATTICEMICO32, 0, 0);
        reset_info->bootstrap_pc = entry;

        if (kernel_size < 0) {
            kernel_size = load_image_targphys(kernel_filename, sdram_base,
                                              sdram_size);
            reset_info->bootstrap_pc = sdram_base;
        }

        if (kernel_size < 0) {
            error_report("could not load kernel '%s'", kernel_filename);
            exit(1);
        }
    }

    if (kernel_cmdline && strlen(kernel_cmdline)) {
        pstrcpy_targphys("cmdline", cmdline_base, TARGET_PAGE_SIZE,
                kernel_cmdline);
        reset_info->cmdline_base = (uint32_t)cmdline_base;
    }

    if (initrd_filename) {
        size_t initrd_size;
        initrd_size = load_image_targphys(initrd_filename, initrd_base,
                initrd_max);
        reset_info->initrd_base = (uint32_t)initrd_base;
        reset_info->initrd_size = (uint32_t)initrd_size;
    }

    qemu_register_reset(main_cpu_reset, reset_info);
}

static void milkymist_machine_init(MachineClass *mc)
{
    mc->desc = "Milkymist One";
    mc->init = milkymist_init;
    mc->is_default = 0;
    mc->default_cpu_type = LM32_CPU_TYPE_NAME("lm32-full");
}

DEFINE_MACHINE("milkymist", milkymist_machine_init)

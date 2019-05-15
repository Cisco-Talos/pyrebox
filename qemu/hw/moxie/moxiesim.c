/*
 * QEMU/moxiesim emulation
 *
 * Emulates a very simple machine model similar to the one used by the
 * GDB moxie simulator.
 *
 * Copyright (c) 2008, 2009, 2010, 2013 Anthony Green
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/sysbus.h"
#include "hw/hw.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/char/serial.h"
#include "exec/address-spaces.h"
#include "elf.h"

#define PHYS_MEM_BASE 0x80000000
#define FIRMWARE_BASE 0x1000
#define FIRMWARE_SIZE (128 * 0x1000)

typedef struct {
    uint64_t ram_size;
    const char *kernel_filename;
    const char *kernel_cmdline;
    const char *initrd_filename;
} LoaderParams;

static void load_kernel(MoxieCPU *cpu, LoaderParams *loader_params)
{
    uint64_t entry, kernel_low, kernel_high;
    int64_t initrd_size;
    long kernel_size;
    ram_addr_t initrd_offset;

    kernel_size = load_elf(loader_params->kernel_filename,  NULL, NULL, NULL,
                           &entry, &kernel_low, &kernel_high, 1, EM_MOXIE,
                           0, 0);

    if (kernel_size <= 0) {
        error_report("could not load kernel '%s'",
                     loader_params->kernel_filename);
        exit(1);
    }

    /* load initrd */
    initrd_size = 0;
    initrd_offset = 0;
    if (loader_params->initrd_filename) {
        initrd_size = get_image_size(loader_params->initrd_filename);
        if (initrd_size > 0) {
            initrd_offset = (kernel_high + ~TARGET_PAGE_MASK)
              & TARGET_PAGE_MASK;
            if (initrd_offset + initrd_size > loader_params->ram_size) {
                error_report("memory too small for initial ram disk '%s'",
                             loader_params->initrd_filename);
                exit(1);
            }
            initrd_size = load_image_targphys(loader_params->initrd_filename,
                                              initrd_offset,
                                              ram_size);
        }
        if (initrd_size == (target_ulong)-1) {
            error_report("could not load initial ram disk '%s'",
                         loader_params->initrd_filename);
            exit(1);
        }
    }
}

static void main_cpu_reset(void *opaque)
{
    MoxieCPU *cpu = opaque;

    cpu_reset(CPU(cpu));
}

static void moxiesim_init(MachineState *machine)
{
    MoxieCPU *cpu = NULL;
    ram_addr_t ram_size = machine->ram_size;
    const char *kernel_filename = machine->kernel_filename;
    const char *kernel_cmdline = machine->kernel_cmdline;
    const char *initrd_filename = machine->initrd_filename;
    CPUMoxieState *env;
    MemoryRegion *address_space_mem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    MemoryRegion *rom = g_new(MemoryRegion, 1);
    hwaddr ram_base = 0x200000;
    LoaderParams loader_params;

    /* Init CPUs. */
    cpu = MOXIE_CPU(cpu_create(machine->cpu_type));
    env = &cpu->env;

    qemu_register_reset(main_cpu_reset, cpu);

    /* Allocate RAM. */
    memory_region_init_ram(ram, NULL, "moxiesim.ram", ram_size, &error_fatal);
    memory_region_add_subregion(address_space_mem, ram_base, ram);

    memory_region_init_ram(rom, NULL, "moxie.rom", FIRMWARE_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), FIRMWARE_BASE, rom);

    if (kernel_filename) {
        loader_params.ram_size = ram_size;
        loader_params.kernel_filename = kernel_filename;
        loader_params.kernel_cmdline = kernel_cmdline;
        loader_params.initrd_filename = initrd_filename;
        load_kernel(cpu, &loader_params);
    }
    if (bios_name) {
        if (load_image_targphys(bios_name, FIRMWARE_BASE, FIRMWARE_SIZE) < 0) {
            error_report("Failed to load firmware '%s'", bios_name);
        }
    }

    /* A single 16450 sits at offset 0x3f8.  */
    if (serial_hd(0)) {
        serial_mm_init(address_space_mem, 0x3f8, 0, env->irq[4],
                       8000000/16, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    }
}

static void moxiesim_machine_init(MachineClass *mc)
{
    mc->desc = "Moxie simulator platform";
    mc->init = moxiesim_init;
    mc->is_default = 1;
    mc->default_cpu_type = MOXIE_CPU_TYPE_NAME("MoxieLite");
}

DEFINE_MACHINE("moxiesim", moxiesim_machine_init)

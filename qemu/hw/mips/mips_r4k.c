/*
 * QEMU/MIPS pseudo-board
 *
 * emulates a simple machine with ISA-like bus.
 * ISA IO space mapped to the 0x14000000 (PHYS) and
 * ISA memory at the 0x10000000 (PHYS, 16Mb in size).
 * All peripherial devices are attached to this "bus" with
 * the standard PC ISA addresses.
*/
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/mips/mips.h"
#include "hw/mips/cpudevs.h"
#include "hw/i386/pc.h"
#include "hw/char/serial.h"
#include "hw/isa/isa.h"
#include "net/net.h"
#include "hw/net/ne2000-isa.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "hw/block/flash.h"
#include "qemu/log.h"
#include "hw/mips/bios.h"
#include "hw/ide.h"
#include "hw/loader.h"
#include "elf.h"
#include "hw/timer/mc146818rtc.h"
#include "hw/input/i8042.h"
#include "hw/timer/i8254.h"
#include "exec/address-spaces.h"
#include "sysemu/qtest.h"
#include "qemu/error-report.h"

#define MAX_IDE_BUS 2

static const int ide_iobase[2] = { 0x1f0, 0x170 };
static const int ide_iobase2[2] = { 0x3f6, 0x376 };
static const int ide_irq[2] = { 14, 15 };

static ISADevice *pit; /* PIT i8254 */

/* i8254 PIT is attached to the IRQ0 at PIC i8259 */

static struct _loaderparams {
    int ram_size;
    const char *kernel_filename;
    const char *kernel_cmdline;
    const char *initrd_filename;
} loaderparams;

static void mips_qemu_write (void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    if ((addr & 0xffff) == 0 && val == 42)
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    else if ((addr & 0xffff) == 4 && val == 42)
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
}

static uint64_t mips_qemu_read (void *opaque, hwaddr addr,
                                unsigned size)
{
    return 0;
}

static const MemoryRegionOps mips_qemu_ops = {
    .read = mips_qemu_read,
    .write = mips_qemu_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

typedef struct ResetData {
    MIPSCPU *cpu;
    uint64_t vector;
} ResetData;

static int64_t load_kernel(void)
{
    const size_t params_size = 264;
    int64_t entry, kernel_high, initrd_size;
    long kernel_size;
    ram_addr_t initrd_offset;
    uint32_t *params_buf;
    int big_endian;

#ifdef TARGET_WORDS_BIGENDIAN
    big_endian = 1;
#else
    big_endian = 0;
#endif
    kernel_size = load_elf(loaderparams.kernel_filename, NULL,
                           cpu_mips_kseg0_to_phys, NULL,
                           (uint64_t *)&entry, NULL,
                           (uint64_t *)&kernel_high, big_endian,
                           EM_MIPS, 1, 0);
    if (kernel_size >= 0) {
        if ((entry & ~0x7fffffffULL) == 0x80000000)
            entry = (int32_t)entry;
    } else {
        error_report("could not load kernel '%s': %s",
                     loaderparams.kernel_filename,
                     load_elf_strerror(kernel_size));
        exit(1);
    }

    /* load initrd */
    initrd_size = 0;
    initrd_offset = 0;
    if (loaderparams.initrd_filename) {
        initrd_size = get_image_size (loaderparams.initrd_filename);
        if (initrd_size > 0) {
            initrd_offset = (kernel_high + ~INITRD_PAGE_MASK) & INITRD_PAGE_MASK;
            if (initrd_offset + initrd_size > ram_size) {
                error_report("memory too small for initial ram disk '%s'",
                             loaderparams.initrd_filename);
                exit(1);
            }
            initrd_size = load_image_targphys(loaderparams.initrd_filename,
                                              initrd_offset,
                                              ram_size - initrd_offset);
        }
        if (initrd_size == (target_ulong) -1) {
            error_report("could not load initial ram disk '%s'",
                         loaderparams.initrd_filename);
            exit(1);
        }
    }

    /* Store command line.  */
    params_buf = g_malloc(params_size);

    params_buf[0] = tswap32(ram_size);
    params_buf[1] = tswap32(0x12345678);

    if (initrd_size > 0) {
        snprintf((char *)params_buf + 8, 256, "rd_start=0x%" PRIx64 " rd_size=%" PRId64 " %s",
                 cpu_mips_phys_to_kseg0(NULL, initrd_offset),
                 initrd_size, loaderparams.kernel_cmdline);
    } else {
        snprintf((char *)params_buf + 8, 256, "%s", loaderparams.kernel_cmdline);
    }

    rom_add_blob_fixed("params", params_buf, params_size,
                       16 * MiB - params_size);

    g_free(params_buf);
    return entry;
}

static void main_cpu_reset(void *opaque)
{
    ResetData *s = (ResetData *)opaque;
    CPUMIPSState *env = &s->cpu->env;

    cpu_reset(CPU(s->cpu));
    env->active_tc.PC = s->vector;
}

static const int sector_len = 32 * KiB;
static
void mips_r4k_init(MachineState *machine)
{
    ram_addr_t ram_size = machine->ram_size;
    const char *kernel_filename = machine->kernel_filename;
    const char *kernel_cmdline = machine->kernel_cmdline;
    const char *initrd_filename = machine->initrd_filename;
    char *filename;
    MemoryRegion *address_space_mem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    MemoryRegion *bios;
    MemoryRegion *iomem = g_new(MemoryRegion, 1);
    MemoryRegion *isa_io = g_new(MemoryRegion, 1);
    MemoryRegion *isa_mem = g_new(MemoryRegion, 1);
    int bios_size;
    MIPSCPU *cpu;
    CPUMIPSState *env;
    ResetData *reset_info;
    int i;
    qemu_irq *i8259;
    ISABus *isa_bus;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    DriveInfo *dinfo;
    int be;

    /* init CPUs */
    cpu = MIPS_CPU(cpu_create(machine->cpu_type));
    env = &cpu->env;

    reset_info = g_malloc0(sizeof(ResetData));
    reset_info->cpu = cpu;
    reset_info->vector = env->active_tc.PC;
    qemu_register_reset(main_cpu_reset, reset_info);

    /* allocate RAM */
    if (ram_size > 256 * MiB) {
        error_report("Too much memory for this machine: %" PRId64 "MB,"
                     " maximum 256MB", ram_size / MiB);
        exit(1);
    }
    memory_region_allocate_system_memory(ram, NULL, "mips_r4k.ram", ram_size);

    memory_region_add_subregion(address_space_mem, 0, ram);

    memory_region_init_io(iomem, NULL, &mips_qemu_ops, NULL, "mips-qemu", 0x10000);
    memory_region_add_subregion(address_space_mem, 0x1fbf0000, iomem);

    /* Try to load a BIOS image. If this fails, we continue regardless,
       but initialize the hardware ourselves. When a kernel gets
       preloaded we also initialize the hardware, since the BIOS wasn't
       run. */
    if (bios_name == NULL)
        bios_name = BIOS_FILENAME;
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    if (filename) {
        bios_size = get_image_size(filename);
    } else {
        bios_size = -1;
    }
#ifdef TARGET_WORDS_BIGENDIAN
    be = 1;
#else
    be = 0;
#endif
    if ((bios_size > 0) && (bios_size <= BIOS_SIZE)) {
        bios = g_new(MemoryRegion, 1);
        memory_region_init_ram(bios, NULL, "mips_r4k.bios", BIOS_SIZE,
                               &error_fatal);
        memory_region_set_readonly(bios, true);
        memory_region_add_subregion(get_system_memory(), 0x1fc00000, bios);

        load_image_targphys(filename, 0x1fc00000, BIOS_SIZE);
    } else if ((dinfo = drive_get(IF_PFLASH, 0, 0)) != NULL) {
        uint32_t mips_rom = 0x00400000;
        if (!pflash_cfi01_register(0x1fc00000, "mips_r4k.bios", mips_rom,
                                   blk_by_legacy_dinfo(dinfo),
                                   sector_len, 4, 0, 0, 0, 0, be)) {
            fprintf(stderr, "qemu: Error registering flash memory.\n");
        }
    } else if (!qtest_enabled()) {
        /* not fatal */
        warn_report("could not load MIPS bios '%s'", bios_name);
    }
    g_free(filename);

    if (kernel_filename) {
        loaderparams.ram_size = ram_size;
        loaderparams.kernel_filename = kernel_filename;
        loaderparams.kernel_cmdline = kernel_cmdline;
        loaderparams.initrd_filename = initrd_filename;
        reset_info->vector = load_kernel();
    }

    /* Init CPU internal devices */
    cpu_mips_irq_init_cpu(cpu);
    cpu_mips_clock_init(cpu);

    /* ISA bus: IO space at 0x14000000, mem space at 0x10000000 */
    memory_region_init_alias(isa_io, NULL, "isa-io",
                             get_system_io(), 0, 0x00010000);
    memory_region_init(isa_mem, NULL, "isa-mem", 0x01000000);
    memory_region_add_subregion(get_system_memory(), 0x14000000, isa_io);
    memory_region_add_subregion(get_system_memory(), 0x10000000, isa_mem);
    isa_bus = isa_bus_new(NULL, isa_mem, get_system_io(), &error_abort);

    /* The PIC is attached to the MIPS CPU INT0 pin */
    i8259 = i8259_init(isa_bus, env->irq[2]);
    isa_bus_irqs(isa_bus, i8259);

    mc146818_rtc_init(isa_bus, 2000, NULL);

    pit = i8254_pit_init(isa_bus, 0x40, 0, NULL);

    serial_hds_isa_init(isa_bus, 0, MAX_ISA_SERIAL_PORTS);

    isa_vga_init(isa_bus);

    if (nd_table[0].used)
        isa_ne2000_init(isa_bus, 0x300, 9, &nd_table[0]);

    ide_drive_get(hd, ARRAY_SIZE(hd));
    for(i = 0; i < MAX_IDE_BUS; i++)
        isa_ide_init(isa_bus, ide_iobase[i], ide_iobase2[i], ide_irq[i],
                     hd[MAX_IDE_DEVS * i],
                     hd[MAX_IDE_DEVS * i + 1]);

    isa_create_simple(isa_bus, TYPE_I8042);
}

static void mips_machine_init(MachineClass *mc)
{
    mc->desc = "mips r4k platform";
    mc->init = mips_r4k_init;
    mc->block_default_type = IF_IDE;
#ifdef TARGET_MIPS64
    mc->default_cpu_type = MIPS_CPU_TYPE_NAME("R4000");
#else
    mc->default_cpu_type = MIPS_CPU_TYPE_NAME("24Kf");
#endif

}

DEFINE_MACHINE("mips", mips_machine_init)

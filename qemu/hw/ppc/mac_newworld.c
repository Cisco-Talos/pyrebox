/*
 * QEMU PowerPC CHRP (currently NewWorld PowerMac) hardware System Emulator
 *
 * Copyright (c) 2004-2007 Fabrice Bellard
 * Copyright (c) 2007 Jocelyn Mayer
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
 *
 * PCI bus layout on a real G5 (U3 based):
 *
 * 0000:f0:0b.0 Host bridge [0600]: Apple Computer Inc. U3 AGP [106b:004b]
 * 0000:f0:10.0 VGA compatible controller [0300]: ATI Technologies Inc RV350 AP [Radeon 9600] [1002:4150]
 * 0001:00:00.0 Host bridge [0600]: Apple Computer Inc. CPC945 HT Bridge [106b:004a]
 * 0001:00:01.0 PCI bridge [0604]: Advanced Micro Devices [AMD] AMD-8131 PCI-X Bridge [1022:7450] (rev 12)
 * 0001:00:02.0 PCI bridge [0604]: Advanced Micro Devices [AMD] AMD-8131 PCI-X Bridge [1022:7450] (rev 12)
 * 0001:00:03.0 PCI bridge [0604]: Apple Computer Inc. K2 HT-PCI Bridge [106b:0045]
 * 0001:00:04.0 PCI bridge [0604]: Apple Computer Inc. K2 HT-PCI Bridge [106b:0046]
 * 0001:00:05.0 PCI bridge [0604]: Apple Computer Inc. K2 HT-PCI Bridge [106b:0047]
 * 0001:00:06.0 PCI bridge [0604]: Apple Computer Inc. K2 HT-PCI Bridge [106b:0048]
 * 0001:00:07.0 PCI bridge [0604]: Apple Computer Inc. K2 HT-PCI Bridge [106b:0049]
 * 0001:01:07.0 Class [ff00]: Apple Computer Inc. K2 KeyLargo Mac/IO [106b:0041] (rev 20)
 * 0001:01:08.0 USB Controller [0c03]: Apple Computer Inc. K2 KeyLargo USB [106b:0040]
 * 0001:01:09.0 USB Controller [0c03]: Apple Computer Inc. K2 KeyLargo USB [106b:0040]
 * 0001:02:0b.0 USB Controller [0c03]: NEC Corporation USB [1033:0035] (rev 43)
 * 0001:02:0b.1 USB Controller [0c03]: NEC Corporation USB [1033:0035] (rev 43)
 * 0001:02:0b.2 USB Controller [0c03]: NEC Corporation USB 2.0 [1033:00e0] (rev 04)
 * 0001:03:0d.0 Class [ff00]: Apple Computer Inc. K2 ATA/100 [106b:0043]
 * 0001:03:0e.0 FireWire (IEEE 1394) [0c00]: Apple Computer Inc. K2 FireWire [106b:0042]
 * 0001:04:0f.0 Ethernet controller [0200]: Apple Computer Inc. K2 GMAC (Sun GEM) [106b:004c]
 * 0001:05:0c.0 IDE interface [0101]: Broadcom K2 SATA [1166:0240]
 *
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/ppc/ppc.h"
#include "hw/ppc/mac.h"
#include "hw/input/adb.h"
#include "hw/ppc/mac_dbdma.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "hw/nvram/fw_cfg.h"
#include "hw/char/escc.h"
#include "hw/misc/macio/macio.h"
#include "hw/ppc/openpic.h"
#include "hw/ide.h"
#include "hw/loader.h"
#include "hw/fw-path-provider.h"
#include "elf.h"
#include "qemu/error-report.h"
#include "sysemu/kvm.h"
#include "kvm_ppc.h"
#include "hw/usb.h"
#include "exec/address-spaces.h"
#include "hw/sysbus.h"
#include "trace.h"

#define MAX_IDE_BUS 2
#define CFG_ADDR 0xf0000510
#define TBFREQ (100UL * 1000UL * 1000UL)
#define CLOCKFREQ (900UL * 1000UL * 1000UL)
#define BUSFREQ (100UL * 1000UL * 1000UL)

#define NDRV_VGA_FILENAME "qemu_vga.ndrv"


static void fw_cfg_boot_set(void *opaque, const char *boot_device,
                            Error **errp)
{
    fw_cfg_modify_i16(opaque, FW_CFG_BOOT_DEVICE, boot_device[0]);
}

static uint64_t translate_kernel_address(void *opaque, uint64_t addr)
{
    return (addr & 0x0fffffff) + KERNEL_LOAD_ADDR;
}

static void ppc_core99_reset(void *opaque)
{
    PowerPCCPU *cpu = opaque;

    cpu_reset(CPU(cpu));
    /* 970 CPUs want to get their initial IP as part of their boot protocol */
    cpu->env.nip = PROM_ADDR + 0x100;
}

/* PowerPC Mac99 hardware initialisation */
static void ppc_core99_init(MachineState *machine)
{
    ram_addr_t ram_size = machine->ram_size;
    const char *kernel_filename = machine->kernel_filename;
    const char *kernel_cmdline = machine->kernel_cmdline;
    const char *initrd_filename = machine->initrd_filename;
    const char *boot_device = machine->boot_order;
    Core99MachineState *core99_machine = CORE99_MACHINE(machine);
    PowerPCCPU *cpu = NULL;
    CPUPPCState *env = NULL;
    char *filename;
    IrqLines *openpic_irqs;
    int linux_boot, i, j, k;
    MemoryRegion *ram = g_new(MemoryRegion, 1), *bios = g_new(MemoryRegion, 1);
    hwaddr kernel_base, initrd_base, cmdline_base = 0;
    long kernel_size, initrd_size;
    UNINHostState *uninorth_pci;
    PCIBus *pci_bus;
    NewWorldMacIOState *macio;
    bool has_pmu, has_adb;
    MACIOIDEState *macio_ide;
    BusState *adb_bus;
    MacIONVRAMState *nvr;
    int bios_size;
    int ppc_boot_device;
    DriveInfo *hd[MAX_IDE_BUS * MAX_IDE_DEVS];
    void *fw_cfg;
    int machine_arch;
    SysBusDevice *s;
    DeviceState *dev, *pic_dev;
    hwaddr nvram_addr = 0xFFF04000;
    uint64_t tbfreq;

    linux_boot = (kernel_filename != NULL);

    /* init CPUs */
    for (i = 0; i < smp_cpus; i++) {
        cpu = POWERPC_CPU(cpu_create(machine->cpu_type));
        env = &cpu->env;

        /* Set time-base frequency to 100 Mhz */
        cpu_ppc_tb_init(env, TBFREQ);
        qemu_register_reset(ppc_core99_reset, cpu);
    }

    /* allocate RAM */
    memory_region_allocate_system_memory(ram, NULL, "ppc_core99.ram", ram_size);
    memory_region_add_subregion(get_system_memory(), 0, ram);

    /* allocate and load BIOS */
    memory_region_init_ram(bios, NULL, "ppc_core99.bios", BIOS_SIZE,
                           &error_fatal);

    if (bios_name == NULL)
        bios_name = PROM_FILENAME;
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
    memory_region_set_readonly(bios, true);
    memory_region_add_subregion(get_system_memory(), PROM_ADDR, bios);

    /* Load OpenBIOS (ELF) */
    if (filename) {
        bios_size = load_elf(filename, NULL, NULL, NULL, NULL,
                             NULL, NULL, 1, PPC_ELF_MACHINE, 0, 0);

        g_free(filename);
    } else {
        bios_size = -1;
    }
    if (bios_size < 0 || bios_size > BIOS_SIZE) {
        error_report("could not load PowerPC bios '%s'", bios_name);
        exit(1);
    }

    if (linux_boot) {
        uint64_t lowaddr = 0;
        int bswap_needed;

#ifdef BSWAP_NEEDED
        bswap_needed = 1;
#else
        bswap_needed = 0;
#endif
        kernel_base = KERNEL_LOAD_ADDR;

        kernel_size = load_elf(kernel_filename, NULL,
                               translate_kernel_address, NULL,
                               NULL, &lowaddr, NULL, 1, PPC_ELF_MACHINE,
                               0, 0);
        if (kernel_size < 0)
            kernel_size = load_aout(kernel_filename, kernel_base,
                                    ram_size - kernel_base, bswap_needed,
                                    TARGET_PAGE_SIZE);
        if (kernel_size < 0)
            kernel_size = load_image_targphys(kernel_filename,
                                              kernel_base,
                                              ram_size - kernel_base);
        if (kernel_size < 0) {
            error_report("could not load kernel '%s'", kernel_filename);
            exit(1);
        }
        /* load initrd */
        if (initrd_filename) {
            initrd_base = TARGET_PAGE_ALIGN(kernel_base + kernel_size + KERNEL_GAP);
            initrd_size = load_image_targphys(initrd_filename, initrd_base,
                                              ram_size - initrd_base);
            if (initrd_size < 0) {
                error_report("could not load initial ram disk '%s'",
                             initrd_filename);
                exit(1);
            }
            cmdline_base = TARGET_PAGE_ALIGN(initrd_base + initrd_size);
        } else {
            initrd_base = 0;
            initrd_size = 0;
            cmdline_base = TARGET_PAGE_ALIGN(kernel_base + kernel_size + KERNEL_GAP);
        }
        ppc_boot_device = 'm';
    } else {
        kernel_base = 0;
        kernel_size = 0;
        initrd_base = 0;
        initrd_size = 0;
        ppc_boot_device = '\0';
        /* We consider that NewWorld PowerMac never have any floppy drive
         * For now, OHW cannot boot from the network.
         */
        for (i = 0; boot_device[i] != '\0'; i++) {
            if (boot_device[i] >= 'c' && boot_device[i] <= 'f') {
                ppc_boot_device = boot_device[i];
                break;
            }
        }
        if (ppc_boot_device == '\0') {
            error_report("No valid boot device for Mac99 machine");
            exit(1);
        }
    }

    /* UniN init */
    dev = qdev_create(NULL, TYPE_UNI_NORTH);
    qdev_init_nofail(dev);
    s = SYS_BUS_DEVICE(dev);
    memory_region_add_subregion(get_system_memory(), 0xf8000000,
                                sysbus_mmio_get_region(s, 0));

    openpic_irqs = g_new0(IrqLines, smp_cpus);
    for (i = 0; i < smp_cpus; i++) {
        /* Mac99 IRQ connection between OpenPIC outputs pins
         * and PowerPC input pins
         */
        switch (PPC_INPUT(env)) {
        case PPC_FLAGS_INPUT_6xx:
            openpic_irqs[i].irq[OPENPIC_OUTPUT_INT] =
                ((qemu_irq *)env->irq_inputs)[PPC6xx_INPUT_INT];
            openpic_irqs[i].irq[OPENPIC_OUTPUT_CINT] =
                ((qemu_irq *)env->irq_inputs)[PPC6xx_INPUT_INT];
            openpic_irqs[i].irq[OPENPIC_OUTPUT_MCK] =
                ((qemu_irq *)env->irq_inputs)[PPC6xx_INPUT_MCP];
            /* Not connected ? */
            openpic_irqs[i].irq[OPENPIC_OUTPUT_DEBUG] = NULL;
            /* Check this */
            openpic_irqs[i].irq[OPENPIC_OUTPUT_RESET] =
                ((qemu_irq *)env->irq_inputs)[PPC6xx_INPUT_HRESET];
            break;
#if defined(TARGET_PPC64)
        case PPC_FLAGS_INPUT_970:
            openpic_irqs[i].irq[OPENPIC_OUTPUT_INT] =
                ((qemu_irq *)env->irq_inputs)[PPC970_INPUT_INT];
            openpic_irqs[i].irq[OPENPIC_OUTPUT_CINT] =
                ((qemu_irq *)env->irq_inputs)[PPC970_INPUT_INT];
            openpic_irqs[i].irq[OPENPIC_OUTPUT_MCK] =
                ((qemu_irq *)env->irq_inputs)[PPC970_INPUT_MCP];
            /* Not connected ? */
            openpic_irqs[i].irq[OPENPIC_OUTPUT_DEBUG] = NULL;
            /* Check this */
            openpic_irqs[i].irq[OPENPIC_OUTPUT_RESET] =
                ((qemu_irq *)env->irq_inputs)[PPC970_INPUT_HRESET];
            break;
#endif /* defined(TARGET_PPC64) */
        default:
            error_report("Bus model not supported on mac99 machine");
            exit(1);
        }
    }

    pic_dev = qdev_create(NULL, TYPE_OPENPIC);
    qdev_prop_set_uint32(pic_dev, "model", OPENPIC_MODEL_KEYLARGO);
    qdev_init_nofail(pic_dev);
    s = SYS_BUS_DEVICE(pic_dev);
    k = 0;
    for (i = 0; i < smp_cpus; i++) {
        for (j = 0; j < OPENPIC_OUTPUT_NB; j++) {
            sysbus_connect_irq(s, k++, openpic_irqs[i].irq[j]);
        }
    }
    g_free(openpic_irqs);

    if (PPC_INPUT(env) == PPC_FLAGS_INPUT_970) {
        /* 970 gets a U3 bus */
        /* Uninorth AGP bus */
        dev = qdev_create(NULL, TYPE_U3_AGP_HOST_BRIDGE);
        object_property_set_link(OBJECT(dev), OBJECT(pic_dev), "pic",
                                 &error_abort);
        qdev_init_nofail(dev);
        uninorth_pci = U3_AGP_HOST_BRIDGE(dev);
        s = SYS_BUS_DEVICE(dev);
        /* PCI hole */
        memory_region_add_subregion(get_system_memory(), 0x80000000ULL,
                                    sysbus_mmio_get_region(s, 2));
        /* Register 8 MB of ISA IO space */
        memory_region_add_subregion(get_system_memory(), 0xf2000000,
                                    sysbus_mmio_get_region(s, 3));
        sysbus_mmio_map(s, 0, 0xf0800000);
        sysbus_mmio_map(s, 1, 0xf0c00000);

        machine_arch = ARCH_MAC99_U3;
    } else {
        /* Use values found on a real PowerMac */
        /* Uninorth AGP bus */
        dev = qdev_create(NULL, TYPE_UNI_NORTH_AGP_HOST_BRIDGE);
        object_property_set_link(OBJECT(dev), OBJECT(pic_dev), "pic",
                                 &error_abort);
        qdev_init_nofail(dev);
        s = SYS_BUS_DEVICE(dev);
        sysbus_mmio_map(s, 0, 0xf0800000);
        sysbus_mmio_map(s, 1, 0xf0c00000);

        /* Uninorth internal bus */
        dev = qdev_create(NULL, TYPE_UNI_NORTH_INTERNAL_PCI_HOST_BRIDGE);
        object_property_set_link(OBJECT(dev), OBJECT(pic_dev), "pic",
                                 &error_abort);
        qdev_init_nofail(dev);
        s = SYS_BUS_DEVICE(dev);
        sysbus_mmio_map(s, 0, 0xf4800000);
        sysbus_mmio_map(s, 1, 0xf4c00000);

        /* Uninorth main bus */
        dev = qdev_create(NULL, TYPE_UNI_NORTH_PCI_HOST_BRIDGE);
        qdev_prop_set_uint32(dev, "ofw-addr", 0xf2000000);
        object_property_set_link(OBJECT(dev), OBJECT(pic_dev), "pic",
                                 &error_abort);
        qdev_init_nofail(dev);
        uninorth_pci = UNI_NORTH_PCI_HOST_BRIDGE(dev);
        s = SYS_BUS_DEVICE(dev);
        /* PCI hole */
        memory_region_add_subregion(get_system_memory(), 0x80000000ULL,
                                    sysbus_mmio_get_region(s, 2));
        /* Register 8 MB of ISA IO space */
        memory_region_add_subregion(get_system_memory(), 0xf2000000,
                                    sysbus_mmio_get_region(s, 3));
        sysbus_mmio_map(s, 0, 0xf2800000);
        sysbus_mmio_map(s, 1, 0xf2c00000);

        machine_arch = ARCH_MAC99;
    }

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    has_pmu = (core99_machine->via_config != CORE99_VIA_CONFIG_CUDA);
    has_adb = (core99_machine->via_config == CORE99_VIA_CONFIG_CUDA ||
               core99_machine->via_config == CORE99_VIA_CONFIG_PMU_ADB);

    /* Timebase Frequency */
    if (kvm_enabled()) {
        tbfreq = kvmppc_get_tbfreq();
    } else {
        tbfreq = TBFREQ;
    }

    /* init basic PC hardware */
    pci_bus = PCI_HOST_BRIDGE(uninorth_pci)->bus;

    /* MacIO */
    macio = NEWWORLD_MACIO(pci_create(pci_bus, -1, TYPE_NEWWORLD_MACIO));
    dev = DEVICE(macio);
    qdev_prop_set_uint64(dev, "frequency", tbfreq);
    qdev_prop_set_bit(dev, "has-pmu", has_pmu);
    qdev_prop_set_bit(dev, "has-adb", has_adb);
    object_property_set_link(OBJECT(macio), OBJECT(pic_dev), "pic",
                             &error_abort);
    qdev_init_nofail(dev);

    /* We only emulate 2 out of 3 IDE controllers for now */
    ide_drive_get(hd, ARRAY_SIZE(hd));

    macio_ide = MACIO_IDE(object_resolve_path_component(OBJECT(macio),
                                                        "ide[0]"));
    macio_ide_init_drives(macio_ide, hd);

    macio_ide = MACIO_IDE(object_resolve_path_component(OBJECT(macio),
                                                        "ide[1]"));
    macio_ide_init_drives(macio_ide, &hd[MAX_IDE_DEVS]);

    if (has_adb) {
        if (has_pmu) {
            dev = DEVICE(object_resolve_path_component(OBJECT(macio), "pmu"));
        } else {
            dev = DEVICE(object_resolve_path_component(OBJECT(macio), "cuda"));
        }

        adb_bus = qdev_get_child_bus(dev, "adb.0");
        dev = qdev_create(adb_bus, TYPE_ADB_KEYBOARD);
        qdev_prop_set_bit(dev, "disable-direct-reg3-writes", true);
        qdev_init_nofail(dev);

        dev = qdev_create(adb_bus, TYPE_ADB_MOUSE);
        qdev_prop_set_bit(dev, "disable-direct-reg3-writes", true);
        qdev_init_nofail(dev);
    }

    if (machine->usb) {
        pci_create_simple(pci_bus, -1, "pci-ohci");

        /* U3 needs to use USB for input because Linux doesn't support via-cuda
        on PPC64 */
        if (!has_adb || machine_arch == ARCH_MAC99_U3) {
            USBBus *usb_bus = usb_bus_find(-1);

            usb_create_simple(usb_bus, "usb-kbd");
            usb_create_simple(usb_bus, "usb-mouse");
        }
    }

    pci_vga_init(pci_bus);

    if (graphic_depth != 15 && graphic_depth != 32 && graphic_depth != 8) {
        graphic_depth = 15;
    }

    for (i = 0; i < nb_nics; i++) {
        pci_nic_init_nofail(&nd_table[i], pci_bus, "sungem", NULL);
    }

    /* The NewWorld NVRAM is not located in the MacIO device */
#ifdef CONFIG_KVM
    if (kvm_enabled() && getpagesize() > 4096) {
        /* We can't combine read-write and read-only in a single page, so
           move the NVRAM out of ROM again for KVM */
        nvram_addr = 0xFFE00000;
    }
#endif
    dev = qdev_create(NULL, TYPE_MACIO_NVRAM);
    qdev_prop_set_uint32(dev, "size", 0x2000);
    qdev_prop_set_uint32(dev, "it_shift", 1);
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, nvram_addr);
    nvr = MACIO_NVRAM(dev);
    pmac_format_nvram_partition(nvr, 0x2000);
    /* No PCI init: the BIOS will do it */

    dev = qdev_create(NULL, TYPE_FW_CFG_MEM);
    fw_cfg = FW_CFG(dev);
    qdev_prop_set_uint32(dev, "data_width", 1);
    qdev_prop_set_bit(dev, "dma_enabled", false);
    object_property_add_child(OBJECT(qdev_get_machine()), TYPE_FW_CFG,
                              OBJECT(fw_cfg), NULL);
    qdev_init_nofail(dev);
    s = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(s, 0, CFG_ADDR);
    sysbus_mmio_map(s, 1, CFG_ADDR + 2);

    fw_cfg_add_i16(fw_cfg, FW_CFG_NB_CPUS, (uint16_t)smp_cpus);
    fw_cfg_add_i16(fw_cfg, FW_CFG_MAX_CPUS, (uint16_t)max_cpus);
    fw_cfg_add_i64(fw_cfg, FW_CFG_RAM_SIZE, (uint64_t)ram_size);
    fw_cfg_add_i16(fw_cfg, FW_CFG_MACHINE_ID, machine_arch);
    fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_ADDR, kernel_base);
    fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_SIZE, kernel_size);
    if (kernel_cmdline) {
        fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_CMDLINE, cmdline_base);
        pstrcpy_targphys("cmdline", cmdline_base, TARGET_PAGE_SIZE, kernel_cmdline);
    } else {
        fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_CMDLINE, 0);
    }
    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_ADDR, initrd_base);
    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_SIZE, initrd_size);
    fw_cfg_add_i16(fw_cfg, FW_CFG_BOOT_DEVICE, ppc_boot_device);

    fw_cfg_add_i16(fw_cfg, FW_CFG_PPC_WIDTH, graphic_width);
    fw_cfg_add_i16(fw_cfg, FW_CFG_PPC_HEIGHT, graphic_height);
    fw_cfg_add_i16(fw_cfg, FW_CFG_PPC_DEPTH, graphic_depth);

    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_VIACONFIG, core99_machine->via_config);

    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_IS_KVM, kvm_enabled());
    if (kvm_enabled()) {
#ifdef CONFIG_KVM
        uint8_t *hypercall;

        hypercall = g_malloc(16);
        kvmppc_get_hypercall(env, hypercall, 16);
        fw_cfg_add_bytes(fw_cfg, FW_CFG_PPC_KVM_HC, hypercall, 16);
        fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_KVM_PID, getpid());
#endif
    }
    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_TBFREQ, tbfreq);
    /* Mac OS X requires a "known good" clock-frequency value; pass it one. */
    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_CLOCKFREQ, CLOCKFREQ);
    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_BUSFREQ, BUSFREQ);
    fw_cfg_add_i32(fw_cfg, FW_CFG_PPC_NVRAM_ADDR, nvram_addr);

    /* MacOS NDRV VGA driver */
    filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, NDRV_VGA_FILENAME);
    if (filename) {
        gchar *ndrv_file;
        gsize ndrv_size;

        if (g_file_get_contents(filename, &ndrv_file, &ndrv_size, NULL)) {
            fw_cfg_add_file(fw_cfg, "ndrv/qemu_vga.ndrv", ndrv_file, ndrv_size);
        }
        g_free(filename);
    }

    qemu_register_boot_set(fw_cfg_boot_set, fw_cfg);
}

/*
 * Implementation of an interface to adjust firmware path
 * for the bootindex property handling.
 */
static char *core99_fw_dev_path(FWPathProvider *p, BusState *bus,
                                DeviceState *dev)
{
    PCIDevice *pci;
    IDEBus *ide_bus;
    IDEState *ide_s;
    MACIOIDEState *macio_ide;

    if (!strcmp(object_get_typename(OBJECT(dev)), "macio-newworld")) {
        pci = PCI_DEVICE(dev);
        return g_strdup_printf("mac-io@%x", PCI_SLOT(pci->devfn));
    }

    if (!strcmp(object_get_typename(OBJECT(dev)), "macio-ide")) {
        macio_ide = MACIO_IDE(dev);
        return g_strdup_printf("ata-3@%x", macio_ide->addr);
    }

    if (!strcmp(object_get_typename(OBJECT(dev)), "ide-drive")) {
        ide_bus = IDE_BUS(qdev_get_parent_bus(dev));
        ide_s = idebus_active_if(ide_bus);

        if (ide_s->drive_kind == IDE_CD) {
            return g_strdup("cdrom");
        }

        return g_strdup("disk");
    }

    if (!strcmp(object_get_typename(OBJECT(dev)), "ide-hd")) {
        return g_strdup("disk");
    }

    if (!strcmp(object_get_typename(OBJECT(dev)), "ide-cd")) {
        return g_strdup("cdrom");
    }

    if (!strcmp(object_get_typename(OBJECT(dev)), "virtio-blk-device")) {
        return g_strdup("disk");
    }

    return NULL;
}
static int core99_kvm_type(MachineState *machine, const char *arg)
{
    /* Always force PR KVM */
    return 2;
}

static void core99_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    FWPathProviderClass *fwc = FW_PATH_PROVIDER_CLASS(oc);

    mc->desc = "Mac99 based PowerMAC";
    mc->init = ppc_core99_init;
    mc->block_default_type = IF_IDE;
    mc->max_cpus = MAX_CPUS;
    mc->default_boot_order = "cd";
    mc->default_display = "std";
    mc->kvm_type = core99_kvm_type;
#ifdef TARGET_PPC64
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("970fx_v3.1");
#else
    mc->default_cpu_type = POWERPC_CPU_TYPE_NAME("7400_v2.9");
#endif
    mc->ignore_boot_device_suffixes = true;
    fwc->get_dev_path = core99_fw_dev_path;
}

static char *core99_get_via_config(Object *obj, Error **errp)
{
    Core99MachineState *cms = CORE99_MACHINE(obj);

    switch (cms->via_config) {
    default:
    case CORE99_VIA_CONFIG_CUDA:
        return g_strdup("cuda");

    case CORE99_VIA_CONFIG_PMU:
        return g_strdup("pmu");

    case CORE99_VIA_CONFIG_PMU_ADB:
        return g_strdup("pmu-adb");
    }
}

static void core99_set_via_config(Object *obj, const char *value, Error **errp)
{
    Core99MachineState *cms = CORE99_MACHINE(obj);

    if (!strcmp(value, "cuda")) {
        cms->via_config = CORE99_VIA_CONFIG_CUDA;
    } else if (!strcmp(value, "pmu")) {
        cms->via_config = CORE99_VIA_CONFIG_PMU;
    } else if (!strcmp(value, "pmu-adb")) {
        cms->via_config = CORE99_VIA_CONFIG_PMU_ADB;
    } else {
        error_setg(errp, "Invalid via value");
        error_append_hint(errp, "Valid values are cuda, pmu, pmu-adb.\n");
    }
}

static void core99_instance_init(Object *obj)
{
    Core99MachineState *cms = CORE99_MACHINE(obj);

    /* Default via_config is CORE99_VIA_CONFIG_CUDA */
    cms->via_config = CORE99_VIA_CONFIG_CUDA;
    object_property_add_str(obj, "via", core99_get_via_config,
                            core99_set_via_config, NULL);
    object_property_set_description(obj, "via",
                                    "Set VIA configuration. "
                                    "Valid values are cuda, pmu and pmu-adb",
                                    NULL);

    return;
}

static const TypeInfo core99_machine_info = {
    .name          = MACHINE_TYPE_NAME("mac99"),
    .parent        = TYPE_MACHINE,
    .class_init    = core99_machine_class_init,
    .instance_init = core99_instance_init,
    .instance_size = sizeof(Core99MachineState),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_FW_PATH_PROVIDER },
        { }
    },
};

static void mac_machine_register_types(void)
{
    type_register_static(&core99_machine_info);
}

type_init(mac_machine_register_types)

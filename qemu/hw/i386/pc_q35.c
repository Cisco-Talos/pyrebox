/*
 * Q35 chipset based pc system emulator
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2009, 2010
 *               Isaku Yamahata <yamahata at valinux co jp>
 *               VA Linux Systems Japan K.K.
 * Copyright (C) 2012 Jason Baron <jbaron@redhat.com>
 *
 * This is based on pc.c, but heavily modified.
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
#include "qemu/units.h"
#include "hw/hw.h"
#include "hw/loader.h"
#include "sysemu/arch_init.h"
#include "hw/i2c/smbus_eeprom.h"
#include "hw/boards.h"
#include "hw/timer/mc146818rtc.h"
#include "hw/xen/xen.h"
#include "sysemu/kvm.h"
#include "kvm_i386.h"
#include "hw/kvm/clock.h"
#include "hw/pci-host/q35.h"
#include "exec/address-spaces.h"
#include "hw/i386/pc.h"
#include "hw/i386/ich9.h"
#include "hw/i386/amd_iommu.h"
#include "hw/i386/intel_iommu.h"
#include "hw/display/ramfb.h"
#include "hw/firmware/smbios.h"
#include "hw/ide/pci.h"
#include "hw/ide/ahci.h"
#include "hw/usb.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "sysemu/numa.h"

/* ICH9 AHCI has 6 ports */
#define MAX_SATA_PORTS     6

struct ehci_companions {
    const char *name;
    int func;
    int port;
};

static const struct ehci_companions ich9_1d[] = {
    { .name = "ich9-usb-uhci1", .func = 0, .port = 0 },
    { .name = "ich9-usb-uhci2", .func = 1, .port = 2 },
    { .name = "ich9-usb-uhci3", .func = 2, .port = 4 },
};

static const struct ehci_companions ich9_1a[] = {
    { .name = "ich9-usb-uhci4", .func = 0, .port = 0 },
    { .name = "ich9-usb-uhci5", .func = 1, .port = 2 },
    { .name = "ich9-usb-uhci6", .func = 2, .port = 4 },
};

static int ehci_create_ich9_with_companions(PCIBus *bus, int slot)
{
    const struct ehci_companions *comp;
    PCIDevice *ehci, *uhci;
    BusState *usbbus;
    const char *name;
    int i;

    switch (slot) {
    case 0x1d:
        name = "ich9-usb-ehci1";
        comp = ich9_1d;
        break;
    case 0x1a:
        name = "ich9-usb-ehci2";
        comp = ich9_1a;
        break;
    default:
        return -1;
    }

    ehci = pci_create_multifunction(bus, PCI_DEVFN(slot, 7), true, name);
    qdev_init_nofail(&ehci->qdev);
    usbbus = QLIST_FIRST(&ehci->qdev.child_bus);

    for (i = 0; i < 3; i++) {
        uhci = pci_create_multifunction(bus, PCI_DEVFN(slot, comp[i].func),
                                        true, comp[i].name);
        qdev_prop_set_string(&uhci->qdev, "masterbus", usbbus->name);
        qdev_prop_set_uint32(&uhci->qdev, "firstport", comp[i].port);
        qdev_init_nofail(&uhci->qdev);
    }
    return 0;
}

/* PC hardware initialisation */
static void pc_q35_init(MachineState *machine)
{
    PCMachineState *pcms = PC_MACHINE(machine);
    PCMachineClass *pcmc = PC_MACHINE_GET_CLASS(pcms);
    Q35PCIHost *q35_host;
    PCIHostState *phb;
    PCIBus *host_bus;
    PCIDevice *lpc;
    DeviceState *lpc_dev;
    BusState *idebus[MAX_SATA_PORTS];
    ISADevice *rtc_state;
    MemoryRegion *system_io = get_system_io();
    MemoryRegion *pci_memory;
    MemoryRegion *rom_memory;
    MemoryRegion *ram_memory;
    GSIState *gsi_state;
    ISABus *isa_bus;
    qemu_irq *i8259;
    int i;
    ICH9LPCState *ich9_lpc;
    PCIDevice *ahci;
    ram_addr_t lowmem;
    DriveInfo *hd[MAX_SATA_PORTS];
    MachineClass *mc = MACHINE_GET_CLASS(machine);

    /* Check whether RAM fits below 4G (leaving 1/2 GByte for IO memory
     * and 256 Mbytes for PCI Express Enhanced Configuration Access Mapping
     * also known as MMCFG).
     * If it doesn't, we need to split it in chunks below and above 4G.
     * In any case, try to make sure that guest addresses aligned at
     * 1G boundaries get mapped to host addresses aligned at 1G boundaries.
     */
    if (machine->ram_size >= 0xb0000000) {
        lowmem = 0x80000000;
    } else {
        lowmem = 0xb0000000;
    }

    /* Handle the machine opt max-ram-below-4g.  It is basically doing
     * min(qemu limit, user limit).
     */
    if (!pcms->max_ram_below_4g) {
        pcms->max_ram_below_4g = 1ULL << 32; /* default: 4G */;
    }
    if (lowmem > pcms->max_ram_below_4g) {
        lowmem = pcms->max_ram_below_4g;
        if (machine->ram_size - lowmem > lowmem &&
            lowmem & (1 * GiB - 1)) {
            warn_report("There is possibly poor performance as the ram size "
                        " (0x%" PRIx64 ") is more then twice the size of"
                        " max-ram-below-4g (%"PRIu64") and"
                        " max-ram-below-4g is not a multiple of 1G.",
                        (uint64_t)machine->ram_size, pcms->max_ram_below_4g);
        }
    }

    if (machine->ram_size >= lowmem) {
        pcms->above_4g_mem_size = machine->ram_size - lowmem;
        pcms->below_4g_mem_size = lowmem;
    } else {
        pcms->above_4g_mem_size = 0;
        pcms->below_4g_mem_size = machine->ram_size;
    }

    if (xen_enabled()) {
        xen_hvm_init(pcms, &ram_memory);
    }

    pc_cpus_init(pcms);

    kvmclock_create();

    /* pci enabled */
    if (pcmc->pci_enabled) {
        pci_memory = g_new(MemoryRegion, 1);
        memory_region_init(pci_memory, NULL, "pci", UINT64_MAX);
        rom_memory = pci_memory;
    } else {
        pci_memory = NULL;
        rom_memory = get_system_memory();
    }

    pc_guest_info_init(pcms);

    if (pcmc->smbios_defaults) {
        /* These values are guest ABI, do not change */
        smbios_set_defaults("QEMU", "Standard PC (Q35 + ICH9, 2009)",
                            mc->name, pcmc->smbios_legacy_mode,
                            pcmc->smbios_uuid_encoded,
                            SMBIOS_ENTRY_POINT_21);
    }

    /* allocate ram and load rom/bios */
    if (!xen_enabled()) {
        pc_memory_init(pcms, get_system_memory(),
                       rom_memory, &ram_memory);
    }

    /* irq lines */
    gsi_state = g_malloc0(sizeof(*gsi_state));
    if (kvm_ioapic_in_kernel()) {
        kvm_pc_setup_irq_routing(pcmc->pci_enabled);
        pcms->gsi = qemu_allocate_irqs(kvm_pc_gsi_handler, gsi_state,
                                       GSI_NUM_PINS);
    } else {
        pcms->gsi = qemu_allocate_irqs(gsi_handler, gsi_state, GSI_NUM_PINS);
    }

    /* create pci host bus */
    q35_host = Q35_HOST_DEVICE(qdev_create(NULL, TYPE_Q35_HOST_DEVICE));

    object_property_add_child(qdev_get_machine(), "q35", OBJECT(q35_host), NULL);
    object_property_set_link(OBJECT(q35_host), OBJECT(ram_memory),
                             MCH_HOST_PROP_RAM_MEM, NULL);
    object_property_set_link(OBJECT(q35_host), OBJECT(pci_memory),
                             MCH_HOST_PROP_PCI_MEM, NULL);
    object_property_set_link(OBJECT(q35_host), OBJECT(get_system_memory()),
                             MCH_HOST_PROP_SYSTEM_MEM, NULL);
    object_property_set_link(OBJECT(q35_host), OBJECT(system_io),
                             MCH_HOST_PROP_IO_MEM, NULL);
    object_property_set_int(OBJECT(q35_host), pcms->below_4g_mem_size,
                            PCI_HOST_BELOW_4G_MEM_SIZE, NULL);
    object_property_set_int(OBJECT(q35_host), pcms->above_4g_mem_size,
                            PCI_HOST_ABOVE_4G_MEM_SIZE, NULL);
    /* pci */
    qdev_init_nofail(DEVICE(q35_host));
    phb = PCI_HOST_BRIDGE(q35_host);
    host_bus = phb->bus;
    /* create ISA bus */
    lpc = pci_create_simple_multifunction(host_bus, PCI_DEVFN(ICH9_LPC_DEV,
                                          ICH9_LPC_FUNC), true,
                                          TYPE_ICH9_LPC_DEVICE);

    object_property_add_link(OBJECT(machine), PC_MACHINE_ACPI_DEVICE_PROP,
                             TYPE_HOTPLUG_HANDLER,
                             (Object **)&pcms->acpi_dev,
                             object_property_allow_set_link,
                             OBJ_PROP_LINK_STRONG, &error_abort);
    object_property_set_link(OBJECT(machine), OBJECT(lpc),
                             PC_MACHINE_ACPI_DEVICE_PROP, &error_abort);

    ich9_lpc = ICH9_LPC_DEVICE(lpc);
    lpc_dev = DEVICE(lpc);
    for (i = 0; i < GSI_NUM_PINS; i++) {
        qdev_connect_gpio_out_named(lpc_dev, ICH9_GPIO_GSI, i, pcms->gsi[i]);
    }
    pci_bus_irqs(host_bus, ich9_lpc_set_irq, ich9_lpc_map_irq, ich9_lpc,
                 ICH9_LPC_NB_PIRQS);
    pci_bus_set_route_irq_fn(host_bus, ich9_route_intx_pin_to_irq);
    isa_bus = ich9_lpc->isa_bus;

    if (kvm_pic_in_kernel()) {
        i8259 = kvm_i8259_init(isa_bus);
    } else if (xen_enabled()) {
        i8259 = xen_interrupt_controller_init();
    } else {
        i8259 = i8259_init(isa_bus, pc_allocate_cpu_irq());
    }

    for (i = 0; i < ISA_NUM_IRQS; i++) {
        gsi_state->i8259_irq[i] = i8259[i];
    }
    g_free(i8259);

    if (pcmc->pci_enabled) {
        ioapic_init_gsi(gsi_state, "q35");
    }

    pc_register_ferr_irq(pcms->gsi[13]);

    assert(pcms->vmport != ON_OFF_AUTO__MAX);
    if (pcms->vmport == ON_OFF_AUTO_AUTO) {
        pcms->vmport = xen_enabled() ? ON_OFF_AUTO_OFF : ON_OFF_AUTO_ON;
    }

    /* init basic PC hardware */
    pc_basic_device_init(isa_bus, pcms->gsi, &rtc_state, !mc->no_floppy,
                         (pcms->vmport != ON_OFF_AUTO_ON), pcms->pit_enabled,
                         0xff0104);

    /* connect pm stuff to lpc */
    ich9_lpc_pm_init(lpc, pc_machine_is_smm_enabled(pcms));

    if (pcms->sata_enabled) {
        /* ahci and SATA device, for q35 1 ahci controller is built-in */
        ahci = pci_create_simple_multifunction(host_bus,
                                               PCI_DEVFN(ICH9_SATA1_DEV,
                                                         ICH9_SATA1_FUNC),
                                               true, "ich9-ahci");
        idebus[0] = qdev_get_child_bus(&ahci->qdev, "ide.0");
        idebus[1] = qdev_get_child_bus(&ahci->qdev, "ide.1");
        g_assert(MAX_SATA_PORTS == ahci_get_num_ports(ahci));
        ide_drive_get(hd, ahci_get_num_ports(ahci));
        ahci_ide_create_devs(ahci, hd);
    } else {
        idebus[0] = idebus[1] = NULL;
    }

    if (machine_usb(machine)) {
        /* Should we create 6 UHCI according to ich9 spec? */
        ehci_create_ich9_with_companions(host_bus, 0x1d);
    }

    if (pcms->smbus_enabled) {
        /* TODO: Populate SPD eeprom data.  */
        smbus_eeprom_init(ich9_smb_init(host_bus,
                                        PCI_DEVFN(ICH9_SMB_DEV, ICH9_SMB_FUNC),
                                        0xb100),
                          8, NULL, 0);
    }

    pc_cmos_init(pcms, idebus[0], idebus[1], rtc_state);

    /* the rest devices to which pci devfn is automatically assigned */
    pc_vga_init(isa_bus, host_bus);
    pc_nic_init(pcmc, isa_bus, host_bus);

    if (machine->nvdimms_state->is_enabled) {
        nvdimm_init_acpi_state(machine->nvdimms_state, system_io,
                               pcms->fw_cfg, OBJECT(pcms));
    }
}

#define DEFINE_Q35_MACHINE(suffix, name, compatfn, optionfn) \
    static void pc_init_##suffix(MachineState *machine) \
    { \
        void (*compat)(MachineState *m) = (compatfn); \
        if (compat) { \
            compat(machine); \
        } \
        pc_q35_init(machine); \
    } \
    DEFINE_PC_MACHINE(suffix, name, pc_init_##suffix, optionfn)


static void pc_q35_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);
    pcmc->default_nic_model = "e1000e";

    m->family = "pc_q35";
    m->desc = "Standard PC (Q35 + ICH9, 2009)";
    m->units_per_default_bus = 1;
    m->default_machine_opts = "firmware=bios-256k.bin";
    m->default_display = "std";
    m->default_kernel_irqchip_split = true;
    m->no_floppy = 1;
    machine_class_allow_dynamic_sysbus_dev(m, TYPE_AMD_IOMMU_DEVICE);
    machine_class_allow_dynamic_sysbus_dev(m, TYPE_INTEL_IOMMU_DEVICE);
    machine_class_allow_dynamic_sysbus_dev(m, TYPE_RAMFB_DEVICE);
    m->max_cpus = 288;
}

static void pc_q35_4_0_machine_options(MachineClass *m)
{
    pc_q35_machine_options(m);
    m->alias = "q35";
}

DEFINE_Q35_MACHINE(v4_0, "pc-q35-4.0", NULL,
                   pc_q35_4_0_machine_options);

static void pc_q35_3_1_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);

    pc_q35_4_0_machine_options(m);
    m->default_kernel_irqchip_split = false;
    m->smbus_no_migration_support = true;
    m->alias = NULL;
    pcmc->pvh_enabled = false;
    compat_props_add(m->compat_props, hw_compat_3_1, hw_compat_3_1_len);
    compat_props_add(m->compat_props, pc_compat_3_1, pc_compat_3_1_len);
}

DEFINE_Q35_MACHINE(v3_1, "pc-q35-3.1", NULL,
                   pc_q35_3_1_machine_options);

static void pc_q35_3_0_machine_options(MachineClass *m)
{
    pc_q35_3_1_machine_options(m);
    compat_props_add(m->compat_props, hw_compat_3_0, hw_compat_3_0_len);
    compat_props_add(m->compat_props, pc_compat_3_0, pc_compat_3_0_len);
}

DEFINE_Q35_MACHINE(v3_0, "pc-q35-3.0", NULL,
                    pc_q35_3_0_machine_options);

static void pc_q35_2_12_machine_options(MachineClass *m)
{
    pc_q35_3_0_machine_options(m);
    compat_props_add(m->compat_props, hw_compat_2_12, hw_compat_2_12_len);
    compat_props_add(m->compat_props, pc_compat_2_12, pc_compat_2_12_len);
}

DEFINE_Q35_MACHINE(v2_12, "pc-q35-2.12", NULL,
                   pc_q35_2_12_machine_options);

static void pc_q35_2_11_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);

    pc_q35_2_12_machine_options(m);
    pcmc->default_nic_model = "e1000";
    compat_props_add(m->compat_props, hw_compat_2_11, hw_compat_2_11_len);
    compat_props_add(m->compat_props, pc_compat_2_11, pc_compat_2_11_len);
}

DEFINE_Q35_MACHINE(v2_11, "pc-q35-2.11", NULL,
                   pc_q35_2_11_machine_options);

static void pc_q35_2_10_machine_options(MachineClass *m)
{
    pc_q35_2_11_machine_options(m);
    compat_props_add(m->compat_props, hw_compat_2_10, hw_compat_2_10_len);
    compat_props_add(m->compat_props, pc_compat_2_10, pc_compat_2_10_len);
    m->numa_auto_assign_ram = numa_legacy_auto_assign_ram;
    m->auto_enable_numa_with_memhp = false;
}

DEFINE_Q35_MACHINE(v2_10, "pc-q35-2.10", NULL,
                   pc_q35_2_10_machine_options);

static void pc_q35_2_9_machine_options(MachineClass *m)
{
    pc_q35_2_10_machine_options(m);
    compat_props_add(m->compat_props, hw_compat_2_9, hw_compat_2_9_len);
    compat_props_add(m->compat_props, pc_compat_2_9, pc_compat_2_9_len);
}

DEFINE_Q35_MACHINE(v2_9, "pc-q35-2.9", NULL,
                   pc_q35_2_9_machine_options);

static void pc_q35_2_8_machine_options(MachineClass *m)
{
    pc_q35_2_9_machine_options(m);
    compat_props_add(m->compat_props, hw_compat_2_8, hw_compat_2_8_len);
    compat_props_add(m->compat_props, pc_compat_2_8, pc_compat_2_8_len);
}

DEFINE_Q35_MACHINE(v2_8, "pc-q35-2.8", NULL,
                   pc_q35_2_8_machine_options);

static void pc_q35_2_7_machine_options(MachineClass *m)
{
    pc_q35_2_8_machine_options(m);
    m->max_cpus = 255;
    compat_props_add(m->compat_props, hw_compat_2_7, hw_compat_2_7_len);
    compat_props_add(m->compat_props, pc_compat_2_7, pc_compat_2_7_len);
}

DEFINE_Q35_MACHINE(v2_7, "pc-q35-2.7", NULL,
                   pc_q35_2_7_machine_options);

static void pc_q35_2_6_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);

    pc_q35_2_7_machine_options(m);
    pcmc->legacy_cpu_hotplug = true;
    pcmc->linuxboot_dma_enabled = false;
    compat_props_add(m->compat_props, hw_compat_2_6, hw_compat_2_6_len);
    compat_props_add(m->compat_props, pc_compat_2_6, pc_compat_2_6_len);
}

DEFINE_Q35_MACHINE(v2_6, "pc-q35-2.6", NULL,
                   pc_q35_2_6_machine_options);

static void pc_q35_2_5_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);

    pc_q35_2_6_machine_options(m);
    pcmc->save_tsc_khz = false;
    m->legacy_fw_cfg_order = 1;
    compat_props_add(m->compat_props, hw_compat_2_5, hw_compat_2_5_len);
    compat_props_add(m->compat_props, pc_compat_2_5, pc_compat_2_5_len);
}

DEFINE_Q35_MACHINE(v2_5, "pc-q35-2.5", NULL,
                   pc_q35_2_5_machine_options);

static void pc_q35_2_4_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);

    pc_q35_2_5_machine_options(m);
    m->hw_version = "2.4.0";
    pcmc->broken_reserved_end = true;
    compat_props_add(m->compat_props, hw_compat_2_4, hw_compat_2_4_len);
    compat_props_add(m->compat_props, pc_compat_2_4, pc_compat_2_4_len);
}

DEFINE_Q35_MACHINE(v2_4, "pc-q35-2.4", NULL,
                   pc_q35_2_4_machine_options);

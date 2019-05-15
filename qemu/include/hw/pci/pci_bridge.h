/*
 * QEMU PCI bridge
 *
 * Copyright (c) 2004 Fabrice Bellard
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * split out pci bus specific stuff from pci.[hc] to pci_bridge.[hc]
 * Copyright (c) 2009 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#ifndef QEMU_PCI_BRIDGE_H
#define QEMU_PCI_BRIDGE_H

#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"

typedef struct PCIBridgeWindows PCIBridgeWindows;

/*
 * Aliases for each of the address space windows that the bridge
 * can forward. Mapped into the bridge's parent's address space,
 * as subregions.
 */
struct PCIBridgeWindows {
    MemoryRegion alias_pref_mem;
    MemoryRegion alias_mem;
    MemoryRegion alias_io;
    /*
     * When bridge control VGA forwarding is enabled, bridges will
     * provide positive decode on the PCI VGA defined I/O port and
     * MMIO ranges.  When enabled forwarding is only qualified on the
     * I/O and memory enable bits in the bridge command register.
     */
    MemoryRegion alias_vga[QEMU_PCI_VGA_NUM_REGIONS];
};

#define TYPE_PCI_BRIDGE "base-pci-bridge"
#define PCI_BRIDGE(obj) OBJECT_CHECK(PCIBridge, (obj), TYPE_PCI_BRIDGE)

struct PCIBridge {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    /* private member */
    PCIBus sec_bus;
    /*
     * Memory regions for the bridge's address spaces.  These regions are not
     * directly added to system_memory/system_io or its descendants.
     * Bridge's secondary bus points to these, so that devices
     * under the bridge see these regions as its address spaces.
     * The regions are as large as the entire address space -
     * they don't take into account any windows.
     */
    MemoryRegion address_space_mem;
    MemoryRegion address_space_io;

    PCIBridgeWindows *windows;

    pci_map_irq_fn map_irq;
    const char *bus_name;
};

#define PCI_BRIDGE_DEV_PROP_CHASSIS_NR "chassis_nr"
#define PCI_BRIDGE_DEV_PROP_MSI        "msi"
#define PCI_BRIDGE_DEV_PROP_SHPC       "shpc"

int pci_bridge_ssvid_init(PCIDevice *dev, uint8_t offset,
                          uint16_t svid, uint16_t ssid,
                          Error **errp);

PCIDevice *pci_bridge_get_device(PCIBus *bus);
PCIBus *pci_bridge_get_sec_bus(PCIBridge *br);

pcibus_t pci_bridge_get_base(const PCIDevice *bridge, uint8_t type);
pcibus_t pci_bridge_get_limit(const PCIDevice *bridge, uint8_t type);

void pci_bridge_update_mappings(PCIBridge *br);
void pci_bridge_write_config(PCIDevice *d,
                             uint32_t address, uint32_t val, int len);
void pci_bridge_disable_base_limit(PCIDevice *dev);
void pci_bridge_reset(DeviceState *qdev);

void pci_bridge_initfn(PCIDevice *pci_dev, const char *typename);
void pci_bridge_exitfn(PCIDevice *pci_dev);

void pci_bridge_dev_plug_cb(HotplugHandler *hotplug_dev, DeviceState *dev,
                            Error **errp);
void pci_bridge_dev_unplug_cb(HotplugHandler *hotplug_dev, DeviceState *dev,
                              Error **errp);
void pci_bridge_dev_unplug_request_cb(HotplugHandler *hotplug_dev,
                                      DeviceState *dev, Error **errp);

/*
 * before qdev initialization(qdev_init()), this function sets bus_name and
 * map_irq callback which are necessry for pci_bridge_initfn() to
 * initialize bus.
 */
void pci_bridge_map_irq(PCIBridge *br, const char* bus_name,
                        pci_map_irq_fn map_irq);

/* TODO: add this define to pci_regs.h in linux and then in qemu. */
#define  PCI_BRIDGE_CTL_VGA_16BIT	0x10	/* VGA 16-bit decode */
#define  PCI_BRIDGE_CTL_DISCARD		0x100	/* Primary discard timer */
#define  PCI_BRIDGE_CTL_SEC_DISCARD	0x200	/* Secondary discard timer */
#define  PCI_BRIDGE_CTL_DISCARD_STATUS	0x400	/* Discard timer status */
#define  PCI_BRIDGE_CTL_DISCARD_SERR	0x800	/* Discard timer SERR# enable */

typedef struct PCIBridgeQemuCap {
    uint8_t id;     /* Standard PCI capability header field */
    uint8_t next;   /* Standard PCI capability header field */
    uint8_t len;    /* Standard PCI vendor-specific capability header field */
    uint8_t type;   /* Red Hat vendor-specific capability type.
                       Types are defined with REDHAT_PCI_CAP_ prefix */

    uint32_t bus_res;   /* Minimum number of buses to reserve */
    uint64_t io;        /* IO space to reserve */
    uint32_t mem;       /* Non-prefetchable memory to reserve */
    /* At most one of the following two fields may be set to a value
     * different from -1 */
    uint32_t mem_pref_32; /* Prefetchable memory to reserve (32-bit MMIO) */
    uint64_t mem_pref_64; /* Prefetchable memory to reserve (64-bit MMIO) */
} PCIBridgeQemuCap;

#define REDHAT_PCI_CAP_RESOURCE_RESERVE 1

/*
 * PCI BUS/IO/MEM/PREFMEM additional resources recorded as a
 * capability in PCI configuration space to reserve on firmware init.
 */
typedef struct PCIResReserve {
    uint32_t bus;
    uint64_t io;
    uint64_t mem_non_pref;
    uint64_t mem_pref_32;
    uint64_t mem_pref_64;
} PCIResReserve;

int pci_bridge_qemu_reserve_cap_init(PCIDevice *dev, int cap_offset,
                               PCIResReserve res_reserve, Error **errp);

#endif /* QEMU_PCI_BRIDGE_H */

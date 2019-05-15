/*
 * Xilinx Zynq MPSoC emulation
 *
 * Copyright (C) 2015 Xilinx Inc
 * Written by Peter Crosthwaite <peter.crosthwaite@xilinx.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/arm/xlnx-zynqmp.h"
#include "hw/intc/arm_gic_common.h"
#include "exec/address-spaces.h"
#include "sysemu/kvm.h"
#include "kvm_arm.h"

#define GIC_NUM_SPI_INTR 160

#define ARM_PHYS_TIMER_PPI  30
#define ARM_VIRT_TIMER_PPI  27
#define ARM_HYP_TIMER_PPI   26
#define ARM_SEC_TIMER_PPI   29
#define GIC_MAINTENANCE_PPI 25

#define GEM_REVISION        0x40070106

#define GIC_BASE_ADDR       0xf9000000
#define GIC_DIST_ADDR       0xf9010000
#define GIC_CPU_ADDR        0xf9020000
#define GIC_VIFACE_ADDR     0xf9040000
#define GIC_VCPU_ADDR       0xf9060000

#define SATA_INTR           133
#define SATA_ADDR           0xFD0C0000
#define SATA_NUM_PORTS      2

#define QSPI_ADDR           0xff0f0000
#define LQSPI_ADDR          0xc0000000
#define QSPI_IRQ            15

#define DP_ADDR             0xfd4a0000
#define DP_IRQ              113

#define DPDMA_ADDR          0xfd4c0000
#define DPDMA_IRQ           116

#define IPI_ADDR            0xFF300000
#define IPI_IRQ             64

#define RTC_ADDR            0xffa60000
#define RTC_IRQ             26

#define SDHCI_CAPABILITIES  0x280737ec6481 /* Datasheet: UG1085 (v1.7) */

static const uint64_t gem_addr[XLNX_ZYNQMP_NUM_GEMS] = {
    0xFF0B0000, 0xFF0C0000, 0xFF0D0000, 0xFF0E0000,
};

static const int gem_intr[XLNX_ZYNQMP_NUM_GEMS] = {
    57, 59, 61, 63,
};

static const uint64_t uart_addr[XLNX_ZYNQMP_NUM_UARTS] = {
    0xFF000000, 0xFF010000,
};

static const int uart_intr[XLNX_ZYNQMP_NUM_UARTS] = {
    21, 22,
};

static const uint64_t sdhci_addr[XLNX_ZYNQMP_NUM_SDHCI] = {
    0xFF160000, 0xFF170000,
};

static const int sdhci_intr[XLNX_ZYNQMP_NUM_SDHCI] = {
    48, 49,
};

static const uint64_t spi_addr[XLNX_ZYNQMP_NUM_SPIS] = {
    0xFF040000, 0xFF050000,
};

static const int spi_intr[XLNX_ZYNQMP_NUM_SPIS] = {
    19, 20,
};

static const uint64_t gdma_ch_addr[XLNX_ZYNQMP_NUM_GDMA_CH] = {
    0xFD500000, 0xFD510000, 0xFD520000, 0xFD530000,
    0xFD540000, 0xFD550000, 0xFD560000, 0xFD570000
};

static const int gdma_ch_intr[XLNX_ZYNQMP_NUM_GDMA_CH] = {
    124, 125, 126, 127, 128, 129, 130, 131
};

static const uint64_t adma_ch_addr[XLNX_ZYNQMP_NUM_ADMA_CH] = {
    0xFFA80000, 0xFFA90000, 0xFFAA0000, 0xFFAB0000,
    0xFFAC0000, 0xFFAD0000, 0xFFAE0000, 0xFFAF0000
};

static const int adma_ch_intr[XLNX_ZYNQMP_NUM_ADMA_CH] = {
    77, 78, 79, 80, 81, 82, 83, 84
};

typedef struct XlnxZynqMPGICRegion {
    int region_index;
    uint32_t address;
    uint32_t offset;
    bool virt;
} XlnxZynqMPGICRegion;

static const XlnxZynqMPGICRegion xlnx_zynqmp_gic_regions[] = {
    /* Distributor */
    {
        .region_index = 0,
        .address = GIC_DIST_ADDR,
        .offset = 0,
        .virt = false
    },

    /* CPU interface */
    {
        .region_index = 1,
        .address = GIC_CPU_ADDR,
        .offset = 0,
        .virt = false
    },
    {
        .region_index = 1,
        .address = GIC_CPU_ADDR + 0x10000,
        .offset = 0x1000,
        .virt = false
    },

    /* Virtual interface */
    {
        .region_index = 2,
        .address = GIC_VIFACE_ADDR,
        .offset = 0,
        .virt = true
    },

    /* Virtual CPU interface */
    {
        .region_index = 3,
        .address = GIC_VCPU_ADDR,
        .offset = 0,
        .virt = true
    },
    {
        .region_index = 3,
        .address = GIC_VCPU_ADDR + 0x10000,
        .offset = 0x1000,
        .virt = true
    },
};

static inline int arm_gic_ppi_index(int cpu_nr, int ppi_index)
{
    return GIC_NUM_SPI_INTR + cpu_nr * GIC_INTERNAL + ppi_index;
}

static void xlnx_zynqmp_create_rpu(XlnxZynqMPState *s, const char *boot_cpu,
                                   Error **errp)
{
    Error *err = NULL;
    int i;
    int num_rpus = MIN(smp_cpus - XLNX_ZYNQMP_NUM_APU_CPUS, XLNX_ZYNQMP_NUM_RPU_CPUS);

    if (num_rpus <= 0) {
        /* Don't create rpu-cluster object if there's nothing to put in it */
        return;
    }

    object_initialize_child(OBJECT(s), "rpu-cluster", &s->rpu_cluster,
                            sizeof(s->rpu_cluster), TYPE_CPU_CLUSTER,
                            &error_abort, NULL);
    qdev_prop_set_uint32(DEVICE(&s->rpu_cluster), "cluster-id", 1);

    for (i = 0; i < num_rpus; i++) {
        char *name;

        object_initialize(&s->rpu_cpu[i], sizeof(s->rpu_cpu[i]),
                          "cortex-r5f-" TYPE_ARM_CPU);
        object_property_add_child(OBJECT(&s->rpu_cluster), "rpu-cpu[*]",
                                  OBJECT(&s->rpu_cpu[i]), &error_abort);

        name = object_get_canonical_path_component(OBJECT(&s->rpu_cpu[i]));
        if (strcmp(name, boot_cpu)) {
            /* Secondary CPUs start in PSCI powered-down state */
            object_property_set_bool(OBJECT(&s->rpu_cpu[i]), true,
                                     "start-powered-off", &error_abort);
        } else {
            s->boot_cpu_ptr = &s->rpu_cpu[i];
        }
        g_free(name);

        object_property_set_bool(OBJECT(&s->rpu_cpu[i]), true, "reset-hivecs",
                                 &error_abort);
        object_property_set_bool(OBJECT(&s->rpu_cpu[i]), true, "realized",
                                 &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
    }

    qdev_init_nofail(DEVICE(&s->rpu_cluster));
}

static void xlnx_zynqmp_init(Object *obj)
{
    XlnxZynqMPState *s = XLNX_ZYNQMP(obj);
    int i;
    int num_apus = MIN(smp_cpus, XLNX_ZYNQMP_NUM_APU_CPUS);

    object_initialize_child(obj, "apu-cluster", &s->apu_cluster,
                            sizeof(s->apu_cluster), TYPE_CPU_CLUSTER,
                            &error_abort, NULL);
    qdev_prop_set_uint32(DEVICE(&s->apu_cluster), "cluster-id", 0);

    for (i = 0; i < num_apus; i++) {
        object_initialize_child(OBJECT(&s->apu_cluster), "apu-cpu[*]",
                                &s->apu_cpu[i], sizeof(s->apu_cpu[i]),
                                "cortex-a53-" TYPE_ARM_CPU, &error_abort,
                                NULL);
    }

    sysbus_init_child_obj(obj, "gic", &s->gic, sizeof(s->gic),
                          gic_class_name());

    for (i = 0; i < XLNX_ZYNQMP_NUM_GEMS; i++) {
        sysbus_init_child_obj(obj, "gem[*]", &s->gem[i], sizeof(s->gem[i]),
                              TYPE_CADENCE_GEM);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_UARTS; i++) {
        sysbus_init_child_obj(obj, "uart[*]", &s->uart[i], sizeof(s->uart[i]),
                              TYPE_CADENCE_UART);
    }

    sysbus_init_child_obj(obj, "sata", &s->sata, sizeof(s->sata),
                          TYPE_SYSBUS_AHCI);

    for (i = 0; i < XLNX_ZYNQMP_NUM_SDHCI; i++) {
        sysbus_init_child_obj(obj, "sdhci[*]", &s->sdhci[i],
                              sizeof(s->sdhci[i]), TYPE_SYSBUS_SDHCI);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_SPIS; i++) {
        sysbus_init_child_obj(obj, "spi[*]", &s->spi[i], sizeof(s->spi[i]),
                              TYPE_XILINX_SPIPS);
    }

    sysbus_init_child_obj(obj, "qspi", &s->qspi, sizeof(s->qspi),
                          TYPE_XLNX_ZYNQMP_QSPIPS);

    sysbus_init_child_obj(obj, "xxxdp", &s->dp, sizeof(s->dp), TYPE_XLNX_DP);

    sysbus_init_child_obj(obj, "dp-dma", &s->dpdma, sizeof(s->dpdma),
                          TYPE_XLNX_DPDMA);

    sysbus_init_child_obj(obj, "ipi", &s->ipi, sizeof(s->ipi),
                          TYPE_XLNX_ZYNQMP_IPI);

    sysbus_init_child_obj(obj, "rtc", &s->rtc, sizeof(s->rtc),
                          TYPE_XLNX_ZYNQMP_RTC);

    for (i = 0; i < XLNX_ZYNQMP_NUM_GDMA_CH; i++) {
        sysbus_init_child_obj(obj, "gdma[*]", &s->gdma[i], sizeof(s->gdma[i]),
                              TYPE_XLNX_ZDMA);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_ADMA_CH; i++) {
        sysbus_init_child_obj(obj, "adma[*]", &s->adma[i], sizeof(s->adma[i]),
                              TYPE_XLNX_ZDMA);
    }
}

static void xlnx_zynqmp_realize(DeviceState *dev, Error **errp)
{
    XlnxZynqMPState *s = XLNX_ZYNQMP(dev);
    MemoryRegion *system_memory = get_system_memory();
    uint8_t i;
    uint64_t ram_size;
    int num_apus = MIN(smp_cpus, XLNX_ZYNQMP_NUM_APU_CPUS);
    const char *boot_cpu = s->boot_cpu ? s->boot_cpu : "apu-cpu[0]";
    ram_addr_t ddr_low_size, ddr_high_size;
    qemu_irq gic_spi[GIC_NUM_SPI_INTR];
    Error *err = NULL;

    ram_size = memory_region_size(s->ddr_ram);

    /* Create the DDR Memory Regions. User friendly checks should happen at
     * the board level
     */
    if (ram_size > XLNX_ZYNQMP_MAX_LOW_RAM_SIZE) {
        /* The RAM size is above the maximum available for the low DDR.
         * Create the high DDR memory region as well.
         */
        assert(ram_size <= XLNX_ZYNQMP_MAX_RAM_SIZE);
        ddr_low_size = XLNX_ZYNQMP_MAX_LOW_RAM_SIZE;
        ddr_high_size = ram_size - XLNX_ZYNQMP_MAX_LOW_RAM_SIZE;

        memory_region_init_alias(&s->ddr_ram_high, NULL,
                                 "ddr-ram-high", s->ddr_ram,
                                  ddr_low_size, ddr_high_size);
        memory_region_add_subregion(get_system_memory(),
                                    XLNX_ZYNQMP_HIGH_RAM_START,
                                    &s->ddr_ram_high);
    } else {
        /* RAM must be non-zero */
        assert(ram_size);
        ddr_low_size = ram_size;
    }

    memory_region_init_alias(&s->ddr_ram_low, NULL,
                             "ddr-ram-low", s->ddr_ram,
                              0, ddr_low_size);
    memory_region_add_subregion(get_system_memory(), 0, &s->ddr_ram_low);

    /* Create the four OCM banks */
    for (i = 0; i < XLNX_ZYNQMP_NUM_OCM_BANKS; i++) {
        char *ocm_name = g_strdup_printf("zynqmp.ocm_ram_bank_%d", i);

        memory_region_init_ram(&s->ocm_ram[i], NULL, ocm_name,
                               XLNX_ZYNQMP_OCM_RAM_SIZE, &error_fatal);
        memory_region_add_subregion(get_system_memory(),
                                    XLNX_ZYNQMP_OCM_RAM_0_ADDRESS +
                                        i * XLNX_ZYNQMP_OCM_RAM_SIZE,
                                    &s->ocm_ram[i]);

        g_free(ocm_name);
    }

    qdev_prop_set_uint32(DEVICE(&s->gic), "num-irq", GIC_NUM_SPI_INTR + 32);
    qdev_prop_set_uint32(DEVICE(&s->gic), "revision", 2);
    qdev_prop_set_uint32(DEVICE(&s->gic), "num-cpu", num_apus);
    qdev_prop_set_bit(DEVICE(&s->gic), "has-security-extensions", s->secure);
    qdev_prop_set_bit(DEVICE(&s->gic),
                      "has-virtualization-extensions", s->virt);

    qdev_init_nofail(DEVICE(&s->apu_cluster));

    /* Realize APUs before realizing the GIC. KVM requires this.  */
    for (i = 0; i < num_apus; i++) {
        char *name;

        object_property_set_int(OBJECT(&s->apu_cpu[i]), QEMU_PSCI_CONDUIT_SMC,
                                "psci-conduit", &error_abort);

        name = object_get_canonical_path_component(OBJECT(&s->apu_cpu[i]));
        if (strcmp(name, boot_cpu)) {
            /* Secondary CPUs start in PSCI powered-down state */
            object_property_set_bool(OBJECT(&s->apu_cpu[i]), true,
                                     "start-powered-off", &error_abort);
        } else {
            s->boot_cpu_ptr = &s->apu_cpu[i];
        }
        g_free(name);

        object_property_set_bool(OBJECT(&s->apu_cpu[i]),
                                 s->secure, "has_el3", NULL);
        object_property_set_bool(OBJECT(&s->apu_cpu[i]),
                                 s->virt, "has_el2", NULL);
        object_property_set_int(OBJECT(&s->apu_cpu[i]), GIC_BASE_ADDR,
                                "reset-cbar", &error_abort);
        object_property_set_int(OBJECT(&s->apu_cpu[i]), num_apus,
                                "core-count", &error_abort);
        object_property_set_bool(OBJECT(&s->apu_cpu[i]), true, "realized",
                                 &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
    }

    object_property_set_bool(OBJECT(&s->gic), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    assert(ARRAY_SIZE(xlnx_zynqmp_gic_regions) == XLNX_ZYNQMP_GIC_REGIONS);
    for (i = 0; i < XLNX_ZYNQMP_GIC_REGIONS; i++) {
        SysBusDevice *gic = SYS_BUS_DEVICE(&s->gic);
        const XlnxZynqMPGICRegion *r = &xlnx_zynqmp_gic_regions[i];
        MemoryRegion *mr;
        uint32_t addr = r->address;
        int j;

        if (r->virt && !s->virt) {
            continue;
        }

        mr = sysbus_mmio_get_region(gic, r->region_index);
        for (j = 0; j < XLNX_ZYNQMP_GIC_ALIASES; j++) {
            MemoryRegion *alias = &s->gic_mr[i][j];

            memory_region_init_alias(alias, OBJECT(s), "zynqmp-gic-alias", mr,
                                     r->offset, XLNX_ZYNQMP_GIC_REGION_SIZE);
            memory_region_add_subregion(system_memory, addr, alias);

            addr += XLNX_ZYNQMP_GIC_REGION_SIZE;
        }
    }

    for (i = 0; i < num_apus; i++) {
        qemu_irq irq;

        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i,
                           qdev_get_gpio_in(DEVICE(&s->apu_cpu[i]),
                                            ARM_CPU_IRQ));
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i + num_apus,
                           qdev_get_gpio_in(DEVICE(&s->apu_cpu[i]),
                                            ARM_CPU_FIQ));
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i + num_apus * 2,
                           qdev_get_gpio_in(DEVICE(&s->apu_cpu[i]),
                                            ARM_CPU_VIRQ));
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i + num_apus * 3,
                           qdev_get_gpio_in(DEVICE(&s->apu_cpu[i]),
                                            ARM_CPU_VFIQ));
        irq = qdev_get_gpio_in(DEVICE(&s->gic),
                               arm_gic_ppi_index(i, ARM_PHYS_TIMER_PPI));
        qdev_connect_gpio_out(DEVICE(&s->apu_cpu[i]), GTIMER_PHYS, irq);
        irq = qdev_get_gpio_in(DEVICE(&s->gic),
                               arm_gic_ppi_index(i, ARM_VIRT_TIMER_PPI));
        qdev_connect_gpio_out(DEVICE(&s->apu_cpu[i]), GTIMER_VIRT, irq);
        irq = qdev_get_gpio_in(DEVICE(&s->gic),
                               arm_gic_ppi_index(i, ARM_HYP_TIMER_PPI));
        qdev_connect_gpio_out(DEVICE(&s->apu_cpu[i]), GTIMER_HYP, irq);
        irq = qdev_get_gpio_in(DEVICE(&s->gic),
                               arm_gic_ppi_index(i, ARM_SEC_TIMER_PPI));
        qdev_connect_gpio_out(DEVICE(&s->apu_cpu[i]), GTIMER_SEC, irq);

        if (s->virt) {
            irq = qdev_get_gpio_in(DEVICE(&s->gic),
                                   arm_gic_ppi_index(i, GIC_MAINTENANCE_PPI));
            sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i + num_apus * 4, irq);
        }
    }

    if (s->has_rpu) {
        info_report("The 'has_rpu' property is no longer required, to use the "
                    "RPUs just use -smp 6.");
    }

    xlnx_zynqmp_create_rpu(s, boot_cpu, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    if (!s->boot_cpu_ptr) {
        error_setg(errp, "ZynqMP Boot cpu %s not found", boot_cpu);
        return;
    }

    for (i = 0; i < GIC_NUM_SPI_INTR; i++) {
        gic_spi[i] = qdev_get_gpio_in(DEVICE(&s->gic), i);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_GEMS; i++) {
        NICInfo *nd = &nd_table[i];

        if (nd->used) {
            qemu_check_nic_model(nd, TYPE_CADENCE_GEM);
            qdev_set_nic_properties(DEVICE(&s->gem[i]), nd);
        }
        object_property_set_int(OBJECT(&s->gem[i]), GEM_REVISION, "revision",
                                &error_abort);
        object_property_set_int(OBJECT(&s->gem[i]), 2, "num-priority-queues",
                                &error_abort);
        object_property_set_bool(OBJECT(&s->gem[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        sysbus_mmio_map(SYS_BUS_DEVICE(&s->gem[i]), 0, gem_addr[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gem[i]), 0,
                           gic_spi[gem_intr[i]]);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_UARTS; i++) {
        qdev_prop_set_chr(DEVICE(&s->uart[i]), "chardev", serial_hd(i));
        object_property_set_bool(OBJECT(&s->uart[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        sysbus_mmio_map(SYS_BUS_DEVICE(&s->uart[i]), 0, uart_addr[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->uart[i]), 0,
                           gic_spi[uart_intr[i]]);
    }

    object_property_set_int(OBJECT(&s->sata), SATA_NUM_PORTS, "num-ports",
                            &error_abort);
    object_property_set_bool(OBJECT(&s->sata), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    sysbus_mmio_map(SYS_BUS_DEVICE(&s->sata), 0, SATA_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->sata), 0, gic_spi[SATA_INTR]);

    for (i = 0; i < XLNX_ZYNQMP_NUM_SDHCI; i++) {
        char *bus_name = g_strdup_printf("sd-bus%d", i);
        SysBusDevice *sbd = SYS_BUS_DEVICE(&s->sdhci[i]);
        Object *sdhci = OBJECT(&s->sdhci[i]);

        /* Compatible with:
         * - SD Host Controller Specification Version 3.00
         * - SDIO Specification Version 3.0
         * - eMMC Specification Version 4.51
         */
        object_property_set_uint(sdhci, 3, "sd-spec-version", &err);
        object_property_set_uint(sdhci, SDHCI_CAPABILITIES, "capareg", &err);
        object_property_set_uint(sdhci, UHS_I, "uhs", &err);
        object_property_set_bool(sdhci, true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        sysbus_mmio_map(sbd, 0, sdhci_addr[i]);
        sysbus_connect_irq(sbd, 0, gic_spi[sdhci_intr[i]]);

        /* Alias controller SD bus to the SoC itself */
        object_property_add_alias(OBJECT(s), bus_name, sdhci, "sd-bus",
                                  &error_abort);
        g_free(bus_name);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_SPIS; i++) {
        gchar *bus_name;

        object_property_set_bool(OBJECT(&s->spi[i]), true, "realized", &err);

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->spi[i]), 0, spi_addr[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->spi[i]), 0,
                           gic_spi[spi_intr[i]]);

        /* Alias controller SPI bus to the SoC itself */
        bus_name = g_strdup_printf("spi%d", i);
        object_property_add_alias(OBJECT(s), bus_name,
                                  OBJECT(&s->spi[i]), "spi0",
                                  &error_abort);
        g_free(bus_name);
    }

    object_property_set_bool(OBJECT(&s->qspi), true, "realized", &err);
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->qspi), 0, QSPI_ADDR);
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->qspi), 1, LQSPI_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->qspi), 0, gic_spi[QSPI_IRQ]);

    for (i = 0; i < XLNX_ZYNQMP_NUM_QSPI_BUS; i++) {
        gchar *bus_name;
        gchar *target_bus;

        /* Alias controller SPI bus to the SoC itself */
        bus_name = g_strdup_printf("qspi%d", i);
        target_bus = g_strdup_printf("spi%d", i);
        object_property_add_alias(OBJECT(s), bus_name,
                                  OBJECT(&s->qspi), target_bus,
                                  &error_abort);
        g_free(bus_name);
        g_free(target_bus);
    }

    object_property_set_bool(OBJECT(&s->dp), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->dp), 0, DP_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->dp), 0, gic_spi[DP_IRQ]);

    object_property_set_bool(OBJECT(&s->dpdma), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    object_property_set_link(OBJECT(&s->dp), OBJECT(&s->dpdma), "dpdma",
                             &error_abort);
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->dpdma), 0, DPDMA_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->dpdma), 0, gic_spi[DPDMA_IRQ]);

    object_property_set_bool(OBJECT(&s->ipi), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->ipi), 0, IPI_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->ipi), 0, gic_spi[IPI_IRQ]);

    object_property_set_bool(OBJECT(&s->rtc), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->rtc), 0, RTC_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->rtc), 0, gic_spi[RTC_IRQ]);

    for (i = 0; i < XLNX_ZYNQMP_NUM_GDMA_CH; i++) {
        object_property_set_uint(OBJECT(&s->gdma[i]), 128, "bus-width", &err);
        object_property_set_bool(OBJECT(&s->gdma[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->gdma[i]), 0, gdma_ch_addr[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gdma[i]), 0,
                           gic_spi[gdma_ch_intr[i]]);
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_ADMA_CH; i++) {
        object_property_set_bool(OBJECT(&s->adma[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->adma[i]), 0, adma_ch_addr[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->adma[i]), 0,
                           gic_spi[adma_ch_intr[i]]);
    }
}

static Property xlnx_zynqmp_props[] = {
    DEFINE_PROP_STRING("boot-cpu", XlnxZynqMPState, boot_cpu),
    DEFINE_PROP_BOOL("secure", XlnxZynqMPState, secure, false),
    DEFINE_PROP_BOOL("virtualization", XlnxZynqMPState, virt, false),
    DEFINE_PROP_BOOL("has_rpu", XlnxZynqMPState, has_rpu, false),
    DEFINE_PROP_LINK("ddr-ram", XlnxZynqMPState, ddr_ram, TYPE_MEMORY_REGION,
                     MemoryRegion *),
    DEFINE_PROP_END_OF_LIST()
};

static void xlnx_zynqmp_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->props = xlnx_zynqmp_props;
    dc->realize = xlnx_zynqmp_realize;
    /* Reason: Uses serial_hds in realize function, thus can't be used twice */
    dc->user_creatable = false;
}

static const TypeInfo xlnx_zynqmp_type_info = {
    .name = TYPE_XLNX_ZYNQMP,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(XlnxZynqMPState),
    .instance_init = xlnx_zynqmp_init,
    .class_init = xlnx_zynqmp_class_init,
};

static void xlnx_zynqmp_register_types(void)
{
    type_register_static(&xlnx_zynqmp_type_info);
}

type_init(xlnx_zynqmp_register_types)

/*
 * Copyright (c) 2015 Jean-Christophe Dubois <jcd@tribudubois.net>
 *
 * i.MX6 SOC emulation.
 *
 * Based on hw/arm/fsl-imx31.c
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/fsl-imx6.h"
#include "sysemu/sysemu.h"
#include "chardev/char.h"
#include "qemu/error-report.h"

#define IMX6_ESDHC_CAPABILITIES     0x057834b4

#define NAME_SIZE 20

static void fsl_imx6_init(Object *obj)
{
    FslIMX6State *s = FSL_IMX6(obj);
    char name[NAME_SIZE];
    int i;

    for (i = 0; i < MIN(smp_cpus, FSL_IMX6_NUM_CPUS); i++) {
        snprintf(name, NAME_SIZE, "cpu%d", i);
        object_initialize_child(obj, name, &s->cpu[i], sizeof(s->cpu[i]),
                                "cortex-a9-" TYPE_ARM_CPU, &error_abort, NULL);
    }

    sysbus_init_child_obj(obj, "a9mpcore", &s->a9mpcore, sizeof(s->a9mpcore),
                          TYPE_A9MPCORE_PRIV);

    sysbus_init_child_obj(obj, "ccm", &s->ccm, sizeof(s->ccm), TYPE_IMX6_CCM);

    sysbus_init_child_obj(obj, "src", &s->src, sizeof(s->src), TYPE_IMX6_SRC);

    for (i = 0; i < FSL_IMX6_NUM_UARTS; i++) {
        snprintf(name, NAME_SIZE, "uart%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->uart[i], sizeof(s->uart[i]),
                              TYPE_IMX_SERIAL);
    }

    sysbus_init_child_obj(obj, "gpt", &s->gpt, sizeof(s->gpt), TYPE_IMX6_GPT);

    for (i = 0; i < FSL_IMX6_NUM_EPITS; i++) {
        snprintf(name, NAME_SIZE, "epit%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->epit[i], sizeof(s->epit[i]),
                              TYPE_IMX_EPIT);
    }

    for (i = 0; i < FSL_IMX6_NUM_I2CS; i++) {
        snprintf(name, NAME_SIZE, "i2c%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->i2c[i], sizeof(s->i2c[i]),
                              TYPE_IMX_I2C);
    }

    for (i = 0; i < FSL_IMX6_NUM_GPIOS; i++) {
        snprintf(name, NAME_SIZE, "gpio%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->gpio[i], sizeof(s->gpio[i]),
                              TYPE_IMX_GPIO);
    }

    for (i = 0; i < FSL_IMX6_NUM_ESDHCS; i++) {
        snprintf(name, NAME_SIZE, "sdhc%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->esdhc[i], sizeof(s->esdhc[i]),
                              TYPE_IMX_USDHC);
    }

    for (i = 0; i < FSL_IMX6_NUM_ECSPIS; i++) {
        snprintf(name, NAME_SIZE, "spi%d", i + 1);
        sysbus_init_child_obj(obj, name, &s->spi[i], sizeof(s->spi[i]),
                              TYPE_IMX_SPI);
    }

    sysbus_init_child_obj(obj, "eth", &s->eth, sizeof(s->eth), TYPE_IMX_ENET);
}

static void fsl_imx6_realize(DeviceState *dev, Error **errp)
{
    FslIMX6State *s = FSL_IMX6(dev);
    uint16_t i;
    Error *err = NULL;

    if (smp_cpus > FSL_IMX6_NUM_CPUS) {
        error_setg(errp, "%s: Only %d CPUs are supported (%d requested)",
                   TYPE_FSL_IMX6, FSL_IMX6_NUM_CPUS, smp_cpus);
        return;
    }

    for (i = 0; i < smp_cpus; i++) {

        /* On uniprocessor, the CBAR is set to 0 */
        if (smp_cpus > 1) {
            object_property_set_int(OBJECT(&s->cpu[i]), FSL_IMX6_A9MPCORE_ADDR,
                                    "reset-cbar", &error_abort);
        }

        /* All CPU but CPU 0 start in power off mode */
        if (i) {
            object_property_set_bool(OBJECT(&s->cpu[i]), true,
                                     "start-powered-off", &error_abort);
        }

        object_property_set_bool(OBJECT(&s->cpu[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
    }

    object_property_set_int(OBJECT(&s->a9mpcore), smp_cpus, "num-cpu",
                            &error_abort);

    object_property_set_int(OBJECT(&s->a9mpcore),
                            FSL_IMX6_MAX_IRQ + GIC_INTERNAL, "num-irq",
                            &error_abort);

    object_property_set_bool(OBJECT(&s->a9mpcore), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->a9mpcore), 0, FSL_IMX6_A9MPCORE_ADDR);

    for (i = 0; i < smp_cpus; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->a9mpcore), i,
                           qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_IRQ));
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->a9mpcore), i + smp_cpus,
                           qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_FIQ));
    }

    object_property_set_bool(OBJECT(&s->ccm), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->ccm), 0, FSL_IMX6_CCM_ADDR);

    object_property_set_bool(OBJECT(&s->src), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->src), 0, FSL_IMX6_SRC_ADDR);

    /* Initialize all UARTs */
    for (i = 0; i < FSL_IMX6_NUM_UARTS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq;
        } serial_table[FSL_IMX6_NUM_UARTS] = {
            { FSL_IMX6_UART1_ADDR, FSL_IMX6_UART1_IRQ },
            { FSL_IMX6_UART2_ADDR, FSL_IMX6_UART2_IRQ },
            { FSL_IMX6_UART3_ADDR, FSL_IMX6_UART3_IRQ },
            { FSL_IMX6_UART4_ADDR, FSL_IMX6_UART4_IRQ },
            { FSL_IMX6_UART5_ADDR, FSL_IMX6_UART5_IRQ },
        };

        qdev_prop_set_chr(DEVICE(&s->uart[i]), "chardev", serial_hd(i));

        object_property_set_bool(OBJECT(&s->uart[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->uart[i]), 0, serial_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->uart[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            serial_table[i].irq));
    }

    s->gpt.ccm = IMX_CCM(&s->ccm);

    object_property_set_bool(OBJECT(&s->gpt), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    sysbus_mmio_map(SYS_BUS_DEVICE(&s->gpt), 0, FSL_IMX6_GPT_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->gpt), 0,
                       qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                        FSL_IMX6_GPT_IRQ));

    /* Initialize all EPIT timers */
    for (i = 0; i < FSL_IMX6_NUM_EPITS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq;
        } epit_table[FSL_IMX6_NUM_EPITS] = {
            { FSL_IMX6_EPIT1_ADDR, FSL_IMX6_EPIT1_IRQ },
            { FSL_IMX6_EPIT2_ADDR, FSL_IMX6_EPIT2_IRQ },
        };

        s->epit[i].ccm = IMX_CCM(&s->ccm);

        object_property_set_bool(OBJECT(&s->epit[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->epit[i]), 0, epit_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->epit[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            epit_table[i].irq));
    }

    /* Initialize all I2C */
    for (i = 0; i < FSL_IMX6_NUM_I2CS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq;
        } i2c_table[FSL_IMX6_NUM_I2CS] = {
            { FSL_IMX6_I2C1_ADDR, FSL_IMX6_I2C1_IRQ },
            { FSL_IMX6_I2C2_ADDR, FSL_IMX6_I2C2_IRQ },
            { FSL_IMX6_I2C3_ADDR, FSL_IMX6_I2C3_IRQ }
        };

        object_property_set_bool(OBJECT(&s->i2c[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->i2c[i]), 0, i2c_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->i2c[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            i2c_table[i].irq));
    }

    /* Initialize all GPIOs */
    for (i = 0; i < FSL_IMX6_NUM_GPIOS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq_low;
            unsigned int irq_high;
        } gpio_table[FSL_IMX6_NUM_GPIOS] = {
            {
                FSL_IMX6_GPIO1_ADDR,
                FSL_IMX6_GPIO1_LOW_IRQ,
                FSL_IMX6_GPIO1_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO2_ADDR,
                FSL_IMX6_GPIO2_LOW_IRQ,
                FSL_IMX6_GPIO2_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO3_ADDR,
                FSL_IMX6_GPIO3_LOW_IRQ,
                FSL_IMX6_GPIO3_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO4_ADDR,
                FSL_IMX6_GPIO4_LOW_IRQ,
                FSL_IMX6_GPIO4_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO5_ADDR,
                FSL_IMX6_GPIO5_LOW_IRQ,
                FSL_IMX6_GPIO5_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO6_ADDR,
                FSL_IMX6_GPIO6_LOW_IRQ,
                FSL_IMX6_GPIO6_HIGH_IRQ
            },
            {
                FSL_IMX6_GPIO7_ADDR,
                FSL_IMX6_GPIO7_LOW_IRQ,
                FSL_IMX6_GPIO7_HIGH_IRQ
            },
        };

        object_property_set_bool(OBJECT(&s->gpio[i]), true, "has-edge-sel",
                                 &error_abort);
        object_property_set_bool(OBJECT(&s->gpio[i]), true, "has-upper-pin-irq",
                                 &error_abort);
        object_property_set_bool(OBJECT(&s->gpio[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->gpio[i]), 0, gpio_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gpio[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            gpio_table[i].irq_low));
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gpio[i]), 1,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            gpio_table[i].irq_high));
    }

    /* Initialize all SDHC */
    for (i = 0; i < FSL_IMX6_NUM_ESDHCS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq;
        } esdhc_table[FSL_IMX6_NUM_ESDHCS] = {
            { FSL_IMX6_uSDHC1_ADDR, FSL_IMX6_uSDHC1_IRQ },
            { FSL_IMX6_uSDHC2_ADDR, FSL_IMX6_uSDHC2_IRQ },
            { FSL_IMX6_uSDHC3_ADDR, FSL_IMX6_uSDHC3_IRQ },
            { FSL_IMX6_uSDHC4_ADDR, FSL_IMX6_uSDHC4_IRQ },
        };

        /* UHS-I SDIO3.0 SDR104 1.8V ADMA */
        object_property_set_uint(OBJECT(&s->esdhc[i]), 3, "sd-spec-version",
                                 &err);
        object_property_set_uint(OBJECT(&s->esdhc[i]), IMX6_ESDHC_CAPABILITIES,
                                 "capareg", &err);
        object_property_set_bool(OBJECT(&s->esdhc[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        sysbus_mmio_map(SYS_BUS_DEVICE(&s->esdhc[i]), 0, esdhc_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->esdhc[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            esdhc_table[i].irq));
    }

    /* Initialize all ECSPI */
    for (i = 0; i < FSL_IMX6_NUM_ECSPIS; i++) {
        static const struct {
            hwaddr addr;
            unsigned int irq;
        } spi_table[FSL_IMX6_NUM_ECSPIS] = {
            { FSL_IMX6_eCSPI1_ADDR, FSL_IMX6_ECSPI1_IRQ },
            { FSL_IMX6_eCSPI2_ADDR, FSL_IMX6_ECSPI2_IRQ },
            { FSL_IMX6_eCSPI3_ADDR, FSL_IMX6_ECSPI3_IRQ },
            { FSL_IMX6_eCSPI4_ADDR, FSL_IMX6_ECSPI4_IRQ },
            { FSL_IMX6_eCSPI5_ADDR, FSL_IMX6_ECSPI5_IRQ },
        };

        /* Initialize the SPI */
        object_property_set_bool(OBJECT(&s->spi[i]), true, "realized", &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        sysbus_mmio_map(SYS_BUS_DEVICE(&s->spi[i]), 0, spi_table[i].addr);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->spi[i]), 0,
                           qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                            spi_table[i].irq));
    }

    qdev_set_nic_properties(DEVICE(&s->eth), &nd_table[0]);
    object_property_set_bool(OBJECT(&s->eth), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->eth), 0, FSL_IMX6_ENET_ADDR);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->eth), 0,
                       qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                        FSL_IMX6_ENET_MAC_IRQ));
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->eth), 1,
                       qdev_get_gpio_in(DEVICE(&s->a9mpcore),
                                        FSL_IMX6_ENET_MAC_1588_IRQ));

    /* ROM memory */
    memory_region_init_rom(&s->rom, NULL, "imx6.rom",
                           FSL_IMX6_ROM_SIZE, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(get_system_memory(), FSL_IMX6_ROM_ADDR,
                                &s->rom);

    /* CAAM memory */
    memory_region_init_rom(&s->caam, NULL, "imx6.caam",
                           FSL_IMX6_CAAM_MEM_SIZE, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(get_system_memory(), FSL_IMX6_CAAM_MEM_ADDR,
                                &s->caam);

    /* OCRAM memory */
    memory_region_init_ram(&s->ocram, NULL, "imx6.ocram", FSL_IMX6_OCRAM_SIZE,
                           &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(get_system_memory(), FSL_IMX6_OCRAM_ADDR,
                                &s->ocram);

    /* internal OCRAM (256 KB) is aliased over 1 MB */
    memory_region_init_alias(&s->ocram_alias, NULL, "imx6.ocram_alias",
                             &s->ocram, 0, FSL_IMX6_OCRAM_ALIAS_SIZE);
    memory_region_add_subregion(get_system_memory(), FSL_IMX6_OCRAM_ALIAS_ADDR,
                                &s->ocram_alias);
}

static void fsl_imx6_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = fsl_imx6_realize;
    dc->desc = "i.MX6 SOC";
    /* Reason: Uses serial_hd() in the realize() function */
    dc->user_creatable = false;
}

static const TypeInfo fsl_imx6_type_info = {
    .name = TYPE_FSL_IMX6,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(FslIMX6State),
    .instance_init = fsl_imx6_init,
    .class_init = fsl_imx6_class_init,
};

static void fsl_imx6_register_types(void)
{
    type_register_static(&fsl_imx6_type_info);
}

type_init(fsl_imx6_register_types)

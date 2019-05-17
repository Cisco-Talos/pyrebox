/*
 * ARM SSE (Subsystems for Embedded): IoTKit, SSE-200
 *
 * Copyright (c) 2018 Linaro Limited
 * Written by Peter Maydell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

/*
 * This is a model of the Arm "Subsystems for Embedded" family of
 * hardware, which include the IoT Kit and the SSE-050, SSE-100 and
 * SSE-200. Currently we model:
 *  - the Arm IoT Kit which is documented in
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ecm0601256/index.html
 *  - the SSE-200 which is documented in
 * http://infocenter.arm.com/help/topic/com.arm.doc.101104_0100_00_en/corelink_sse200_subsystem_for_embedded_technical_reference_manual_101104_0100_00_en.pdf
 *
 * The IoTKit contains:
 *  a Cortex-M33
 *  the IDAU
 *  some timers and watchdogs
 *  two peripheral protection controllers
 *  a memory protection controller
 *  a security controller
 *  a bus fabric which arranges that some parts of the address
 *  space are secure and non-secure aliases of each other
 * The SSE-200 additionally contains:
 *  a second Cortex-M33
 *  two Message Handling Units (MHUs)
 *  an optional CryptoCell (which we do not model)
 *  more SRAM banks with associated MPCs
 *  multiple Power Policy Units (PPUs)
 *  a control interface for an icache for each CPU
 *  per-CPU identity and control register blocks
 *
 * QEMU interface:
 *  + QOM property "memory" is a MemoryRegion containing the devices provided
 *    by the board model.
 *  + QOM property "MAINCLK" is the frequency of the main system clock
 *  + QOM property "EXP_NUMIRQ" sets the number of expansion interrupts.
 *    (In hardware, the SSE-200 permits the number of expansion interrupts
 *    for the two CPUs to be configured separately, but we restrict it to
 *    being the same for both, to avoid having to have separate Property
 *    lists for different variants. This restriction can be relaxed later
 *    if necessary.)
 *  + QOM property "SRAM_ADDR_WIDTH" sets the number of bits used for the
 *    address of each SRAM bank (and thus the total amount of internal SRAM)
 *  + QOM property "init-svtor" sets the initial value of the CPU SVTOR register
 *    (where it expects to load the PC and SP from the vector table on reset)
 *  + Named GPIO inputs "EXP_IRQ" 0..n are the expansion interrupts for CPU 0,
 *    which are wired to its NVIC lines 32 .. n+32
 *  + Named GPIO inputs "EXP_CPU1_IRQ" 0..n are the expansion interrupts for
 *    CPU 1, which are wired to its NVIC lines 32 .. n+32
 *  + sysbus MMIO region 0 is the "AHB Slave Expansion" which allows
 *    bus master devices in the board model to make transactions into
 *    all the devices and memory areas in the IoTKit
 * Controlling up to 4 AHB expansion PPBs which a system using the IoTKit
 * might provide:
 *  + named GPIO outputs apb_ppcexp{0,1,2,3}_nonsec[0..15]
 *  + named GPIO outputs apb_ppcexp{0,1,2,3}_ap[0..15]
 *  + named GPIO outputs apb_ppcexp{0,1,2,3}_irq_enable
 *  + named GPIO outputs apb_ppcexp{0,1,2,3}_irq_clear
 *  + named GPIO inputs apb_ppcexp{0,1,2,3}_irq_status
 * Controlling each of the 4 expansion AHB PPCs which a system using the IoTKit
 * might provide:
 *  + named GPIO outputs ahb_ppcexp{0,1,2,3}_nonsec[0..15]
 *  + named GPIO outputs ahb_ppcexp{0,1,2,3}_ap[0..15]
 *  + named GPIO outputs ahb_ppcexp{0,1,2,3}_irq_enable
 *  + named GPIO outputs ahb_ppcexp{0,1,2,3}_irq_clear
 *  + named GPIO inputs ahb_ppcexp{0,1,2,3}_irq_status
 * Controlling each of the 16 expansion MPCs which a system using the IoTKit
 * might provide:
 *  + named GPIO inputs mpcexp_status[0..15]
 * Controlling each of the 16 expansion MSCs which a system using the IoTKit
 * might provide:
 *  + named GPIO inputs mscexp_status[0..15]
 *  + named GPIO outputs mscexp_clear[0..15]
 *  + named GPIO outputs mscexp_ns[0..15]
 */

#ifndef ARMSSE_H
#define ARMSSE_H

#include "hw/sysbus.h"
#include "hw/arm/armv7m.h"
#include "hw/misc/iotkit-secctl.h"
#include "hw/misc/tz-ppc.h"
#include "hw/misc/tz-mpc.h"
#include "hw/timer/cmsdk-apb-timer.h"
#include "hw/timer/cmsdk-apb-dualtimer.h"
#include "hw/watchdog/cmsdk-apb-watchdog.h"
#include "hw/misc/iotkit-sysctl.h"
#include "hw/misc/iotkit-sysinfo.h"
#include "hw/misc/armsse-cpuid.h"
#include "hw/misc/armsse-mhu.h"
#include "hw/misc/unimp.h"
#include "hw/or-irq.h"
#include "hw/core/split-irq.h"
#include "hw/cpu/cluster.h"

#define TYPE_ARMSSE "arm-sse"
#define ARMSSE(obj) OBJECT_CHECK(ARMSSE, (obj), TYPE_ARMSSE)

/*
 * These type names are for specific IoTKit subsystems; other than
 * instantiating them, code using these devices should always handle
 * them via the ARMSSE base class, so they have no IOTKIT() etc macros.
 */
#define TYPE_IOTKIT "iotkit"
#define TYPE_SSE200 "sse-200"

/* We have an IRQ splitter and an OR gate input for each external PPC
 * and the 2 internal PPCs
 */
#define NUM_EXTERNAL_PPCS (IOTS_NUM_AHB_EXP_PPC + IOTS_NUM_APB_EXP_PPC)
#define NUM_PPCS (NUM_EXTERNAL_PPCS + 2)

#define MAX_SRAM_BANKS 4
#if MAX_SRAM_BANKS > IOTS_NUM_MPC
#error Too many SRAM banks
#endif

#define SSE_MAX_CPUS 2

/* These define what each PPU in the ppu[] index is for */
#define CPU0CORE_PPU 0
#define CPU1CORE_PPU 1
#define DBG_PPU 2
#define RAM0_PPU 3
#define RAM1_PPU 4
#define RAM2_PPU 5
#define RAM3_PPU 6
#define NUM_PPUS 7

typedef struct ARMSSE {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    ARMv7MState armv7m[SSE_MAX_CPUS];
    CPUClusterState cluster[SSE_MAX_CPUS];
    IoTKitSecCtl secctl;
    TZPPC apb_ppc0;
    TZPPC apb_ppc1;
    TZMPC mpc[IOTS_NUM_MPC];
    CMSDKAPBTIMER timer0;
    CMSDKAPBTIMER timer1;
    CMSDKAPBTIMER s32ktimer;
    qemu_or_irq ppc_irq_orgate;
    SplitIRQ sec_resp_splitter;
    SplitIRQ ppc_irq_splitter[NUM_PPCS];
    SplitIRQ mpc_irq_splitter[IOTS_NUM_EXP_MPC + IOTS_NUM_MPC];
    qemu_or_irq mpc_irq_orgate;
    qemu_or_irq nmi_orgate;

    SplitIRQ cpu_irq_splitter[32];

    CMSDKAPBDualTimer dualtimer;

    CMSDKAPBWatchdog s32kwatchdog;
    CMSDKAPBWatchdog nswatchdog;
    CMSDKAPBWatchdog swatchdog;

    IoTKitSysCtl sysctl;
    IoTKitSysCtl sysinfo;

    ARMSSEMHU mhu[2];
    UnimplementedDeviceState ppu[NUM_PPUS];
    UnimplementedDeviceState cachectrl[SSE_MAX_CPUS];
    UnimplementedDeviceState cpusecctrl[SSE_MAX_CPUS];

    ARMSSECPUID cpuid[SSE_MAX_CPUS];

    /*
     * 'container' holds all devices seen by all CPUs.
     * 'cpu_container[i]' is the view that CPU i has: this has the
     * per-CPU devices of that CPU, plus as the background 'container'
     * (or an alias of it, since we can only use it directly once).
     * container_alias[i] is the alias of 'container' used by CPU i+1;
     * CPU 0 can use 'container' directly.
     */
    MemoryRegion container;
    MemoryRegion container_alias[SSE_MAX_CPUS - 1];
    MemoryRegion cpu_container[SSE_MAX_CPUS];
    MemoryRegion alias1;
    MemoryRegion alias2;
    MemoryRegion alias3[SSE_MAX_CPUS];
    MemoryRegion sram[MAX_SRAM_BANKS];

    qemu_irq *exp_irqs[SSE_MAX_CPUS];
    qemu_irq ppc0_irq;
    qemu_irq ppc1_irq;
    qemu_irq sec_resp_cfg;
    qemu_irq sec_resp_cfg_in;
    qemu_irq nsc_cfg_in;

    qemu_irq irq_status_in[NUM_EXTERNAL_PPCS];
    qemu_irq mpcexp_status_in[IOTS_NUM_EXP_MPC];

    uint32_t nsccfg;

    /* Properties */
    MemoryRegion *board_memory;
    uint32_t exp_numirq;
    uint32_t mainclk_frq;
    uint32_t sram_addr_width;
    uint32_t init_svtor;
} ARMSSE;

typedef struct ARMSSEInfo ARMSSEInfo;

typedef struct ARMSSEClass {
    DeviceClass parent_class;
    const ARMSSEInfo *info;
} ARMSSEClass;

#define ARMSSE_CLASS(klass) \
    OBJECT_CLASS_CHECK(ARMSSEClass, (klass), TYPE_ARMSSE)
#define ARMSSE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(ARMSSEClass, (obj), TYPE_ARMSSE)

#endif

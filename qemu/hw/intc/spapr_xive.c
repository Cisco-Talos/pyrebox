/*
 * QEMU PowerPC sPAPR XIVE interrupt controller model
 *
 * Copyright (c) 2017-2018, IBM Corporation.
 *
 * This code is licensed under the GPL version 2 or later. See the
 * COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "target/ppc/cpu.h"
#include "sysemu/cpus.h"
#include "monitor/monitor.h"
#include "hw/ppc/fdt.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_cpu_core.h"
#include "hw/ppc/spapr_xive.h"
#include "hw/ppc/xive.h"
#include "hw/ppc/xive_regs.h"

/*
 * XIVE Virtualization Controller BAR and Thread Managment BAR that we
 * use for the ESB pages and the TIMA pages
 */
#define SPAPR_XIVE_VC_BASE   0x0006010000000000ull
#define SPAPR_XIVE_TM_BASE   0x0006030203180000ull

/*
 * The allocation of VP blocks is a complex operation in OPAL and the
 * VP identifiers have a relation with the number of HW chips, the
 * size of the VP blocks, VP grouping, etc. The QEMU sPAPR XIVE
 * controller model does not have the same constraints and can use a
 * simple mapping scheme of the CPU vcpu_id
 *
 * These identifiers are never returned to the OS.
 */

#define SPAPR_XIVE_NVT_BASE 0x400

/*
 * The sPAPR machine has a unique XIVE IC device. Assign a fixed value
 * to the controller block id value. It can nevertheless be changed
 * for testing purpose.
 */
#define SPAPR_XIVE_BLOCK_ID 0x0

/*
 * sPAPR NVT and END indexing helpers
 */
static uint32_t spapr_xive_nvt_to_target(uint8_t nvt_blk, uint32_t nvt_idx)
{
    return nvt_idx - SPAPR_XIVE_NVT_BASE;
}

static void spapr_xive_cpu_to_nvt(PowerPCCPU *cpu,
                                  uint8_t *out_nvt_blk, uint32_t *out_nvt_idx)
{
    assert(cpu);

    if (out_nvt_blk) {
        *out_nvt_blk = SPAPR_XIVE_BLOCK_ID;
    }

    if (out_nvt_blk) {
        *out_nvt_idx = SPAPR_XIVE_NVT_BASE + cpu->vcpu_id;
    }
}

static int spapr_xive_target_to_nvt(uint32_t target,
                                    uint8_t *out_nvt_blk, uint32_t *out_nvt_idx)
{
    PowerPCCPU *cpu = spapr_find_cpu(target);

    if (!cpu) {
        return -1;
    }

    spapr_xive_cpu_to_nvt(cpu, out_nvt_blk, out_nvt_idx);
    return 0;
}

/*
 * sPAPR END indexing uses a simple mapping of the CPU vcpu_id, 8
 * priorities per CPU
 */
static void spapr_xive_cpu_to_end(PowerPCCPU *cpu, uint8_t prio,
                                  uint8_t *out_end_blk, uint32_t *out_end_idx)
{
    assert(cpu);

    if (out_end_blk) {
        *out_end_blk = SPAPR_XIVE_BLOCK_ID;
    }

    if (out_end_idx) {
        *out_end_idx = (cpu->vcpu_id << 3) + prio;
    }
}

static int spapr_xive_target_to_end(uint32_t target, uint8_t prio,
                                    uint8_t *out_end_blk, uint32_t *out_end_idx)
{
    PowerPCCPU *cpu = spapr_find_cpu(target);

    if (!cpu) {
        return -1;
    }

    spapr_xive_cpu_to_end(cpu, prio, out_end_blk, out_end_idx);
    return 0;
}

/*
 * On sPAPR machines, use a simplified output for the XIVE END
 * structure dumping only the information related to the OS EQ.
 */
static void spapr_xive_end_pic_print_info(SpaprXive *xive, XiveEND *end,
                                          Monitor *mon)
{
    uint32_t qindex = xive_get_field32(END_W1_PAGE_OFF, end->w1);
    uint32_t qgen = xive_get_field32(END_W1_GENERATION, end->w1);
    uint32_t qsize = xive_get_field32(END_W0_QSIZE, end->w0);
    uint32_t qentries = 1 << (qsize + 10);
    uint32_t nvt = xive_get_field32(END_W6_NVT_INDEX, end->w6);
    uint8_t priority = xive_get_field32(END_W7_F0_PRIORITY, end->w7);

    monitor_printf(mon, "%3d/%d % 6d/%5d ^%d",
                   spapr_xive_nvt_to_target(0, nvt),
                   priority, qindex, qentries, qgen);

    xive_end_queue_pic_print_info(end, 6, mon);
    monitor_printf(mon, "]");
}

void spapr_xive_pic_print_info(SpaprXive *xive, Monitor *mon)
{
    XiveSource *xsrc = &xive->source;
    int i;

    monitor_printf(mon, "  LSIN         PQ    EISN     CPU/PRIO EQ\n");

    for (i = 0; i < xive->nr_irqs; i++) {
        uint8_t pq = xive_source_esb_get(xsrc, i);
        XiveEAS *eas = &xive->eat[i];

        if (!xive_eas_is_valid(eas)) {
            continue;
        }

        monitor_printf(mon, "  %08x %s %c%c%c %s %08x ", i,
                       xive_source_irq_is_lsi(xsrc, i) ? "LSI" : "MSI",
                       pq & XIVE_ESB_VAL_P ? 'P' : '-',
                       pq & XIVE_ESB_VAL_Q ? 'Q' : '-',
                       xsrc->status[i] & XIVE_STATUS_ASSERTED ? 'A' : ' ',
                       xive_eas_is_masked(eas) ? "M" : " ",
                       (int) xive_get_field64(EAS_END_DATA, eas->w));

        if (!xive_eas_is_masked(eas)) {
            uint32_t end_idx = xive_get_field64(EAS_END_INDEX, eas->w);
            XiveEND *end;

            assert(end_idx < xive->nr_ends);
            end = &xive->endt[end_idx];

            if (xive_end_is_valid(end)) {
                spapr_xive_end_pic_print_info(xive, end, mon);
            }
        }
        monitor_printf(mon, "\n");
    }
}

static void spapr_xive_map_mmio(SpaprXive *xive)
{
    sysbus_mmio_map(SYS_BUS_DEVICE(xive), 0, xive->vc_base);
    sysbus_mmio_map(SYS_BUS_DEVICE(xive), 1, xive->end_base);
    sysbus_mmio_map(SYS_BUS_DEVICE(xive), 2, xive->tm_base);
}

void spapr_xive_mmio_set_enabled(SpaprXive *xive, bool enable)
{
    memory_region_set_enabled(&xive->source.esb_mmio, enable);
    memory_region_set_enabled(&xive->tm_mmio, enable);

    /* Disable the END ESBs until a guest OS makes use of them */
    memory_region_set_enabled(&xive->end_source.esb_mmio, false);
}

/*
 * When a Virtual Processor is scheduled to run on a HW thread, the
 * hypervisor pushes its identifier in the OS CAM line. Emulate the
 * same behavior under QEMU.
 */
void spapr_xive_set_tctx_os_cam(XiveTCTX *tctx)
{
    uint8_t  nvt_blk;
    uint32_t nvt_idx;
    uint32_t nvt_cam;

    spapr_xive_cpu_to_nvt(POWERPC_CPU(tctx->cs), &nvt_blk, &nvt_idx);

    nvt_cam = cpu_to_be32(TM_QW1W2_VO | xive_nvt_cam_line(nvt_blk, nvt_idx));
    memcpy(&tctx->regs[TM_QW1_OS + TM_WORD2], &nvt_cam, 4);
}

static void spapr_xive_end_reset(XiveEND *end)
{
    memset(end, 0, sizeof(*end));

    /* switch off the escalation and notification ESBs */
    end->w1 = cpu_to_be32(END_W1_ESe_Q | END_W1_ESn_Q);
}

static void spapr_xive_reset(void *dev)
{
    SpaprXive *xive = SPAPR_XIVE(dev);
    int i;

    /*
     * The XiveSource has its own reset handler, which mask off all
     * IRQs (!P|Q)
     */

    /* Mask all valid EASs in the IRQ number space. */
    for (i = 0; i < xive->nr_irqs; i++) {
        XiveEAS *eas = &xive->eat[i];
        if (xive_eas_is_valid(eas)) {
            eas->w = cpu_to_be64(EAS_VALID | EAS_MASKED);
        } else {
            eas->w = 0;
        }
    }

    /* Clear all ENDs */
    for (i = 0; i < xive->nr_ends; i++) {
        spapr_xive_end_reset(&xive->endt[i]);
    }
}

static void spapr_xive_instance_init(Object *obj)
{
    SpaprXive *xive = SPAPR_XIVE(obj);

    object_initialize_child(obj, "source", &xive->source, sizeof(xive->source),
                            TYPE_XIVE_SOURCE, &error_abort, NULL);

    object_initialize_child(obj, "end_source", &xive->end_source,
                            sizeof(xive->end_source), TYPE_XIVE_END_SOURCE,
                            &error_abort, NULL);
}

static void spapr_xive_realize(DeviceState *dev, Error **errp)
{
    SpaprXive *xive = SPAPR_XIVE(dev);
    XiveSource *xsrc = &xive->source;
    XiveENDSource *end_xsrc = &xive->end_source;
    Error *local_err = NULL;

    if (!xive->nr_irqs) {
        error_setg(errp, "Number of interrupt needs to be greater 0");
        return;
    }

    if (!xive->nr_ends) {
        error_setg(errp, "Number of interrupt needs to be greater 0");
        return;
    }

    /*
     * Initialize the internal sources, for IPIs and virtual devices.
     */
    object_property_set_int(OBJECT(xsrc), xive->nr_irqs, "nr-irqs",
                            &error_fatal);
    object_property_add_const_link(OBJECT(xsrc), "xive", OBJECT(xive),
                                   &error_fatal);
    object_property_set_bool(OBJECT(xsrc), true, "realized", &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    /*
     * Initialize the END ESB source
     */
    object_property_set_int(OBJECT(end_xsrc), xive->nr_irqs, "nr-ends",
                            &error_fatal);
    object_property_add_const_link(OBJECT(end_xsrc), "xive", OBJECT(xive),
                                   &error_fatal);
    object_property_set_bool(OBJECT(end_xsrc), true, "realized", &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    /* Set the mapping address of the END ESB pages after the source ESBs */
    xive->end_base = xive->vc_base + (1ull << xsrc->esb_shift) * xsrc->nr_irqs;

    /*
     * Allocate the routing tables
     */
    xive->eat = g_new0(XiveEAS, xive->nr_irqs);
    xive->endt = g_new0(XiveEND, xive->nr_ends);

    /* TIMA initialization */
    memory_region_init_io(&xive->tm_mmio, OBJECT(xive), &xive_tm_ops, xive,
                          "xive.tima", 4ull << TM_SHIFT);

    /* Define all XIVE MMIO regions on SysBus */
    sysbus_init_mmio(SYS_BUS_DEVICE(xive), &xsrc->esb_mmio);
    sysbus_init_mmio(SYS_BUS_DEVICE(xive), &end_xsrc->esb_mmio);
    sysbus_init_mmio(SYS_BUS_DEVICE(xive), &xive->tm_mmio);

    /* Map all regions */
    spapr_xive_map_mmio(xive);

    xive->nodename = g_strdup_printf("interrupt-controller@%" PRIx64,
                           xive->tm_base + XIVE_TM_USER_PAGE * (1 << TM_SHIFT));

    qemu_register_reset(spapr_xive_reset, dev);
}

static int spapr_xive_get_eas(XiveRouter *xrtr, uint8_t eas_blk,
                              uint32_t eas_idx, XiveEAS *eas)
{
    SpaprXive *xive = SPAPR_XIVE(xrtr);

    if (eas_idx >= xive->nr_irqs) {
        return -1;
    }

    *eas = xive->eat[eas_idx];
    return 0;
}

static int spapr_xive_get_end(XiveRouter *xrtr,
                              uint8_t end_blk, uint32_t end_idx, XiveEND *end)
{
    SpaprXive *xive = SPAPR_XIVE(xrtr);

    if (end_idx >= xive->nr_ends) {
        return -1;
    }

    memcpy(end, &xive->endt[end_idx], sizeof(XiveEND));
    return 0;
}

static int spapr_xive_write_end(XiveRouter *xrtr, uint8_t end_blk,
                                uint32_t end_idx, XiveEND *end,
                                uint8_t word_number)
{
    SpaprXive *xive = SPAPR_XIVE(xrtr);

    if (end_idx >= xive->nr_ends) {
        return -1;
    }

    memcpy(&xive->endt[end_idx], end, sizeof(XiveEND));
    return 0;
}

static int spapr_xive_get_nvt(XiveRouter *xrtr,
                              uint8_t nvt_blk, uint32_t nvt_idx, XiveNVT *nvt)
{
    uint32_t vcpu_id = spapr_xive_nvt_to_target(nvt_blk, nvt_idx);
    PowerPCCPU *cpu = spapr_find_cpu(vcpu_id);

    if (!cpu) {
        /* TODO: should we assert() if we can find a NVT ? */
        return -1;
    }

    /*
     * sPAPR does not maintain a NVT table. Return that the NVT is
     * valid if we have found a matching CPU
     */
    nvt->w0 = cpu_to_be32(NVT_W0_VALID);
    return 0;
}

static int spapr_xive_write_nvt(XiveRouter *xrtr, uint8_t nvt_blk,
                                uint32_t nvt_idx, XiveNVT *nvt,
                                uint8_t word_number)
{
    /*
     * We don't need to write back to the NVTs because the sPAPR
     * machine should never hit a non-scheduled NVT. It should never
     * get called.
     */
    g_assert_not_reached();
}

static XiveTCTX *spapr_xive_get_tctx(XiveRouter *xrtr, CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);

    return spapr_cpu_state(cpu)->tctx;
}

static const VMStateDescription vmstate_spapr_xive_end = {
    .name = TYPE_SPAPR_XIVE "/end",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField []) {
        VMSTATE_UINT32(w0, XiveEND),
        VMSTATE_UINT32(w1, XiveEND),
        VMSTATE_UINT32(w2, XiveEND),
        VMSTATE_UINT32(w3, XiveEND),
        VMSTATE_UINT32(w4, XiveEND),
        VMSTATE_UINT32(w5, XiveEND),
        VMSTATE_UINT32(w6, XiveEND),
        VMSTATE_UINT32(w7, XiveEND),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_spapr_xive_eas = {
    .name = TYPE_SPAPR_XIVE "/eas",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField []) {
        VMSTATE_UINT64(w, XiveEAS),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_spapr_xive = {
    .name = TYPE_SPAPR_XIVE,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_EQUAL(nr_irqs, SpaprXive, NULL),
        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(eat, SpaprXive, nr_irqs,
                                     vmstate_spapr_xive_eas, XiveEAS),
        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(endt, SpaprXive, nr_ends,
                                             vmstate_spapr_xive_end, XiveEND),
        VMSTATE_END_OF_LIST()
    },
};

static Property spapr_xive_properties[] = {
    DEFINE_PROP_UINT32("nr-irqs", SpaprXive, nr_irqs, 0),
    DEFINE_PROP_UINT32("nr-ends", SpaprXive, nr_ends, 0),
    DEFINE_PROP_UINT64("vc-base", SpaprXive, vc_base, SPAPR_XIVE_VC_BASE),
    DEFINE_PROP_UINT64("tm-base", SpaprXive, tm_base, SPAPR_XIVE_TM_BASE),
    DEFINE_PROP_END_OF_LIST(),
};

static void spapr_xive_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    XiveRouterClass *xrc = XIVE_ROUTER_CLASS(klass);

    dc->desc    = "sPAPR XIVE Interrupt Controller";
    dc->props   = spapr_xive_properties;
    dc->realize = spapr_xive_realize;
    dc->vmsd    = &vmstate_spapr_xive;

    xrc->get_eas = spapr_xive_get_eas;
    xrc->get_end = spapr_xive_get_end;
    xrc->write_end = spapr_xive_write_end;
    xrc->get_nvt = spapr_xive_get_nvt;
    xrc->write_nvt = spapr_xive_write_nvt;
    xrc->get_tctx = spapr_xive_get_tctx;
}

static const TypeInfo spapr_xive_info = {
    .name = TYPE_SPAPR_XIVE,
    .parent = TYPE_XIVE_ROUTER,
    .instance_init = spapr_xive_instance_init,
    .instance_size = sizeof(SpaprXive),
    .class_init = spapr_xive_class_init,
};

static void spapr_xive_register_types(void)
{
    type_register_static(&spapr_xive_info);
}

type_init(spapr_xive_register_types)

bool spapr_xive_irq_claim(SpaprXive *xive, uint32_t lisn, bool lsi)
{
    XiveSource *xsrc = &xive->source;

    if (lisn >= xive->nr_irqs) {
        return false;
    }

    xive->eat[lisn].w |= cpu_to_be64(EAS_VALID);
    if (lsi) {
        xive_source_irq_set_lsi(xsrc, lisn);
    }
    return true;
}

bool spapr_xive_irq_free(SpaprXive *xive, uint32_t lisn)
{
    if (lisn >= xive->nr_irqs) {
        return false;
    }

    xive->eat[lisn].w &= cpu_to_be64(~EAS_VALID);
    return true;
}

/*
 * XIVE hcalls
 *
 * The terminology used by the XIVE hcalls is the following :
 *
 *   TARGET vCPU number
 *   EQ     Event Queue assigned by OS to receive event data
 *   ESB    page for source interrupt management
 *   LISN   Logical Interrupt Source Number identifying a source in the
 *          machine
 *   EISN   Effective Interrupt Source Number used by guest OS to
 *          identify source in the guest
 *
 * The EAS, END, NVT structures are not exposed.
 */

/*
 * Linux hosts under OPAL reserve priority 7 for their own escalation
 * interrupts (DD2.X POWER9). So we only allow the guest to use
 * priorities [0..6].
 */
static bool spapr_xive_priority_is_reserved(uint8_t priority)
{
    switch (priority) {
    case 0 ... 6:
        return false;
    case 7: /* OPAL escalation queue */
    default:
        return true;
    }
}

/*
 * The H_INT_GET_SOURCE_INFO hcall() is used to obtain the logical
 * real address of the MMIO page through which the Event State Buffer
 * entry associated with the value of the "lisn" parameter is managed.
 *
 * Parameters:
 * Input
 * - R4: "flags"
 *         Bits 0-63 reserved
 * - R5: "lisn" is per "interrupts", "interrupt-map", or
 *       "ibm,xive-lisn-ranges" properties, or as returned by the
 *       ibm,query-interrupt-source-number RTAS call, or as returned
 *       by the H_ALLOCATE_VAS_WINDOW hcall
 *
 * Output
 * - R4: "flags"
 *         Bits 0-59: Reserved
 *         Bit 60: H_INT_ESB must be used for Event State Buffer
 *                 management
 *         Bit 61: 1 == LSI  0 == MSI
 *         Bit 62: the full function page supports trigger
 *         Bit 63: Store EOI Supported
 * - R5: Logical Real address of full function Event State Buffer
 *       management page, -1 if H_INT_ESB hcall flag is set to 1.
 * - R6: Logical Real Address of trigger only Event State Buffer
 *       management page or -1.
 * - R7: Power of 2 page size for the ESB management pages returned in
 *       R5 and R6.
 */

#define SPAPR_XIVE_SRC_H_INT_ESB     PPC_BIT(60) /* ESB manage with H_INT_ESB */
#define SPAPR_XIVE_SRC_LSI           PPC_BIT(61) /* Virtual LSI type */
#define SPAPR_XIVE_SRC_TRIGGER       PPC_BIT(62) /* Trigger and management
                                                    on same page */
#define SPAPR_XIVE_SRC_STORE_EOI     PPC_BIT(63) /* Store EOI support */

static target_ulong h_int_get_source_info(PowerPCCPU *cpu,
                                          SpaprMachineState *spapr,
                                          target_ulong opcode,
                                          target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    XiveSource *xsrc = &xive->source;
    target_ulong flags  = args[0];
    target_ulong lisn   = args[1];

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags) {
        return H_PARAMETER;
    }

    if (lisn >= xive->nr_irqs) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Unknown LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    if (!xive_eas_is_valid(&xive->eat[lisn])) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Invalid LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    /*
     * All sources are emulated under the main XIVE object and share
     * the same characteristics.
     */
    args[0] = 0;
    if (!xive_source_esb_has_2page(xsrc)) {
        args[0] |= SPAPR_XIVE_SRC_TRIGGER;
    }
    if (xsrc->esb_flags & XIVE_SRC_STORE_EOI) {
        args[0] |= SPAPR_XIVE_SRC_STORE_EOI;
    }

    /*
     * Force the use of the H_INT_ESB hcall in case of an LSI
     * interrupt. This is necessary under KVM to re-trigger the
     * interrupt if the level is still asserted
     */
    if (xive_source_irq_is_lsi(xsrc, lisn)) {
        args[0] |= SPAPR_XIVE_SRC_H_INT_ESB | SPAPR_XIVE_SRC_LSI;
    }

    if (!(args[0] & SPAPR_XIVE_SRC_H_INT_ESB)) {
        args[1] = xive->vc_base + xive_source_esb_mgmt(xsrc, lisn);
    } else {
        args[1] = -1;
    }

    if (xive_source_esb_has_2page(xsrc) &&
        !(args[0] & SPAPR_XIVE_SRC_H_INT_ESB)) {
        args[2] = xive->vc_base + xive_source_esb_page(xsrc, lisn);
    } else {
        args[2] = -1;
    }

    if (xive_source_esb_has_2page(xsrc)) {
        args[3] = xsrc->esb_shift - 1;
    } else {
        args[3] = xsrc->esb_shift;
    }

    return H_SUCCESS;
}

/*
 * The H_INT_SET_SOURCE_CONFIG hcall() is used to assign a Logical
 * Interrupt Source to a target. The Logical Interrupt Source is
 * designated with the "lisn" parameter and the target is designated
 * with the "target" and "priority" parameters.  Upon return from the
 * hcall(), no additional interrupts will be directed to the old EQ.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-61: Reserved
 *         Bit 62: set the "eisn" in the EAS
 *         Bit 63: masks the interrupt source in the hardware interrupt
 *       control structure. An interrupt masked by this mechanism will
 *       be dropped, but it's source state bits will still be
 *       set. There is no race-free way of unmasking and restoring the
 *       source. Thus this should only be used in interrupts that are
 *       also masked at the source, and only in cases where the
 *       interrupt is not meant to be used for a large amount of time
 *       because no valid target exists for it for example
 * - R5: "lisn" is per "interrupts", "interrupt-map", or
 *       "ibm,xive-lisn-ranges" properties, or as returned by the
 *       ibm,query-interrupt-source-number RTAS call, or as returned by
 *       the H_ALLOCATE_VAS_WINDOW hcall
 * - R6: "target" is per "ibm,ppc-interrupt-server#s" or
 *       "ibm,ppc-interrupt-gserver#s"
 * - R7: "priority" is a valid priority not in
 *       "ibm,plat-res-int-priorities"
 * - R8: "eisn" is the guest EISN associated with the "lisn"
 *
 * Output:
 * - None
 */

#define SPAPR_XIVE_SRC_SET_EISN PPC_BIT(62)
#define SPAPR_XIVE_SRC_MASK     PPC_BIT(63)

static target_ulong h_int_set_source_config(PowerPCCPU *cpu,
                                            SpaprMachineState *spapr,
                                            target_ulong opcode,
                                            target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    XiveEAS eas, new_eas;
    target_ulong flags    = args[0];
    target_ulong lisn     = args[1];
    target_ulong target   = args[2];
    target_ulong priority = args[3];
    target_ulong eisn     = args[4];
    uint8_t end_blk;
    uint32_t end_idx;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags & ~(SPAPR_XIVE_SRC_SET_EISN | SPAPR_XIVE_SRC_MASK)) {
        return H_PARAMETER;
    }

    if (lisn >= xive->nr_irqs) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Unknown LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    eas = xive->eat[lisn];
    if (!xive_eas_is_valid(&eas)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Invalid LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    /* priority 0xff is used to reset the EAS */
    if (priority == 0xff) {
        new_eas.w = cpu_to_be64(EAS_VALID | EAS_MASKED);
        goto out;
    }

    if (flags & SPAPR_XIVE_SRC_MASK) {
        new_eas.w = eas.w | cpu_to_be64(EAS_MASKED);
    } else {
        new_eas.w = eas.w & cpu_to_be64(~EAS_MASKED);
    }

    if (spapr_xive_priority_is_reserved(priority)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: priority " TARGET_FMT_ld
                      " is reserved\n", priority);
        return H_P4;
    }

    /*
     * Validate that "target" is part of the list of threads allocated
     * to the partition. For that, find the END corresponding to the
     * target.
     */
    if (spapr_xive_target_to_end(target, priority, &end_blk, &end_idx)) {
        return H_P3;
    }

    new_eas.w = xive_set_field64(EAS_END_BLOCK, new_eas.w, end_blk);
    new_eas.w = xive_set_field64(EAS_END_INDEX, new_eas.w, end_idx);

    if (flags & SPAPR_XIVE_SRC_SET_EISN) {
        new_eas.w = xive_set_field64(EAS_END_DATA, new_eas.w, eisn);
    }

out:
    xive->eat[lisn] = new_eas;
    return H_SUCCESS;
}

/*
 * The H_INT_GET_SOURCE_CONFIG hcall() is used to determine to which
 * target/priority pair is assigned to the specified Logical Interrupt
 * Source.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63 Reserved
 * - R5: "lisn" is per "interrupts", "interrupt-map", or
 *       "ibm,xive-lisn-ranges" properties, or as returned by the
 *       ibm,query-interrupt-source-number RTAS call, or as
 *       returned by the H_ALLOCATE_VAS_WINDOW hcall
 *
 * Output:
 * - R4: Target to which the specified Logical Interrupt Source is
 *       assigned
 * - R5: Priority to which the specified Logical Interrupt Source is
 *       assigned
 * - R6: EISN for the specified Logical Interrupt Source (this will be
 *       equivalent to the LISN if not changed by H_INT_SET_SOURCE_CONFIG)
 */
static target_ulong h_int_get_source_config(PowerPCCPU *cpu,
                                            SpaprMachineState *spapr,
                                            target_ulong opcode,
                                            target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    target_ulong flags = args[0];
    target_ulong lisn = args[1];
    XiveEAS eas;
    XiveEND *end;
    uint8_t nvt_blk;
    uint32_t end_idx, nvt_idx;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags) {
        return H_PARAMETER;
    }

    if (lisn >= xive->nr_irqs) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Unknown LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    eas = xive->eat[lisn];
    if (!xive_eas_is_valid(&eas)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Invalid LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    /* EAS_END_BLOCK is unused on sPAPR */
    end_idx = xive_get_field64(EAS_END_INDEX, eas.w);

    assert(end_idx < xive->nr_ends);
    end = &xive->endt[end_idx];

    nvt_blk = xive_get_field32(END_W6_NVT_BLOCK, end->w6);
    nvt_idx = xive_get_field32(END_W6_NVT_INDEX, end->w6);
    args[0] = spapr_xive_nvt_to_target(nvt_blk, nvt_idx);

    if (xive_eas_is_masked(&eas)) {
        args[1] = 0xff;
    } else {
        args[1] = xive_get_field32(END_W7_F0_PRIORITY, end->w7);
    }

    args[2] = xive_get_field64(EAS_END_DATA, eas.w);

    return H_SUCCESS;
}

/*
 * The H_INT_GET_QUEUE_INFO hcall() is used to get the logical real
 * address of the notification management page associated with the
 * specified target and priority.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63 Reserved
 * - R5: "target" is per "ibm,ppc-interrupt-server#s" or
 *       "ibm,ppc-interrupt-gserver#s"
 * - R6: "priority" is a valid priority not in
 *       "ibm,plat-res-int-priorities"
 *
 * Output:
 * - R4: Logical real address of notification page
 * - R5: Power of 2 page size of the notification page
 */
static target_ulong h_int_get_queue_info(PowerPCCPU *cpu,
                                         SpaprMachineState *spapr,
                                         target_ulong opcode,
                                         target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    XiveENDSource *end_xsrc = &xive->end_source;
    target_ulong flags = args[0];
    target_ulong target = args[1];
    target_ulong priority = args[2];
    XiveEND *end;
    uint8_t end_blk;
    uint32_t end_idx;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags) {
        return H_PARAMETER;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    if (spapr_xive_priority_is_reserved(priority)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: priority " TARGET_FMT_ld
                      " is reserved\n", priority);
        return H_P3;
    }

    /*
     * Validate that "target" is part of the list of threads allocated
     * to the partition. For that, find the END corresponding to the
     * target.
     */
    if (spapr_xive_target_to_end(target, priority, &end_blk, &end_idx)) {
        return H_P2;
    }

    assert(end_idx < xive->nr_ends);
    end = &xive->endt[end_idx];

    args[0] = xive->end_base + (1ull << (end_xsrc->esb_shift + 1)) * end_idx;
    if (xive_end_is_enqueue(end)) {
        args[1] = xive_get_field32(END_W0_QSIZE, end->w0) + 12;
    } else {
        args[1] = 0;
    }

    return H_SUCCESS;
}

/*
 * The H_INT_SET_QUEUE_CONFIG hcall() is used to set or reset a EQ for
 * a given "target" and "priority".  It is also used to set the
 * notification config associated with the EQ.  An EQ size of 0 is
 * used to reset the EQ config for a given target and priority. If
 * resetting the EQ config, the END associated with the given "target"
 * and "priority" will be changed to disable queueing.
 *
 * Upon return from the hcall(), no additional interrupts will be
 * directed to the old EQ (if one was set). The old EQ (if one was
 * set) should be investigated for interrupts that occurred prior to
 * or during the hcall().
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-62: Reserved
 *         Bit 63: Unconditional Notify (n) per the XIVE spec
 * - R5: "target" is per "ibm,ppc-interrupt-server#s" or
 *       "ibm,ppc-interrupt-gserver#s"
 * - R6: "priority" is a valid priority not in
 *       "ibm,plat-res-int-priorities"
 * - R7: "eventQueue": The logical real address of the start of the EQ
 * - R8: "eventQueueSize": The power of 2 EQ size per "ibm,xive-eq-sizes"
 *
 * Output:
 * - None
 */

#define SPAPR_XIVE_END_ALWAYS_NOTIFY PPC_BIT(63)

static target_ulong h_int_set_queue_config(PowerPCCPU *cpu,
                                           SpaprMachineState *spapr,
                                           target_ulong opcode,
                                           target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    target_ulong flags = args[0];
    target_ulong target = args[1];
    target_ulong priority = args[2];
    target_ulong qpage = args[3];
    target_ulong qsize = args[4];
    XiveEND end;
    uint8_t end_blk, nvt_blk;
    uint32_t end_idx, nvt_idx;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags & ~SPAPR_XIVE_END_ALWAYS_NOTIFY) {
        return H_PARAMETER;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    if (spapr_xive_priority_is_reserved(priority)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: priority " TARGET_FMT_ld
                      " is reserved\n", priority);
        return H_P3;
    }

    /*
     * Validate that "target" is part of the list of threads allocated
     * to the partition. For that, find the END corresponding to the
     * target.
     */

    if (spapr_xive_target_to_end(target, priority, &end_blk, &end_idx)) {
        return H_P2;
    }

    assert(end_idx < xive->nr_ends);
    memcpy(&end, &xive->endt[end_idx], sizeof(XiveEND));

    switch (qsize) {
    case 12:
    case 16:
    case 21:
    case 24:
        end.w2 = cpu_to_be32((qpage >> 32) & 0x0fffffff);
        end.w3 = cpu_to_be32(qpage & 0xffffffff);
        end.w0 |= cpu_to_be32(END_W0_ENQUEUE);
        end.w0 = xive_set_field32(END_W0_QSIZE, end.w0, qsize - 12);
        break;
    case 0:
        /* reset queue and disable queueing */
        spapr_xive_end_reset(&end);
        goto out;

    default:
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: invalid EQ size %"PRIx64"\n",
                      qsize);
        return H_P5;
    }

    if (qsize) {
        hwaddr plen = 1 << qsize;
        void *eq;

        /*
         * Validate the guest EQ. We should also check that the queue
         * has been zeroed by the OS.
         */
        eq = address_space_map(CPU(cpu)->as, qpage, &plen, true,
                               MEMTXATTRS_UNSPECIFIED);
        if (plen != 1 << qsize) {
            qemu_log_mask(LOG_GUEST_ERROR, "XIVE: failed to map EQ @0x%"
                          HWADDR_PRIx "\n", qpage);
            return H_P4;
        }
        address_space_unmap(CPU(cpu)->as, eq, plen, true, plen);
    }

    /* "target" should have been validated above */
    if (spapr_xive_target_to_nvt(target, &nvt_blk, &nvt_idx)) {
        g_assert_not_reached();
    }

    /*
     * Ensure the priority and target are correctly set (they will not
     * be right after allocation)
     */
    end.w6 = xive_set_field32(END_W6_NVT_BLOCK, 0ul, nvt_blk) |
        xive_set_field32(END_W6_NVT_INDEX, 0ul, nvt_idx);
    end.w7 = xive_set_field32(END_W7_F0_PRIORITY, 0ul, priority);

    if (flags & SPAPR_XIVE_END_ALWAYS_NOTIFY) {
        end.w0 |= cpu_to_be32(END_W0_UCOND_NOTIFY);
    } else {
        end.w0 &= cpu_to_be32((uint32_t)~END_W0_UCOND_NOTIFY);
    }

    /*
     * The generation bit for the END starts at 1 and The END page
     * offset counter starts at 0.
     */
    end.w1 = cpu_to_be32(END_W1_GENERATION) |
        xive_set_field32(END_W1_PAGE_OFF, 0ul, 0ul);
    end.w0 |= cpu_to_be32(END_W0_VALID);

    /*
     * TODO: issue syncs required to ensure all in-flight interrupts
     * are complete on the old END
     */

out:
    /* Update END */
    memcpy(&xive->endt[end_idx], &end, sizeof(XiveEND));
    return H_SUCCESS;
}

/*
 * The H_INT_GET_QUEUE_CONFIG hcall() is used to get a EQ for a given
 * target and priority.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-62: Reserved
 *         Bit 63: Debug: Return debug data
 * - R5: "target" is per "ibm,ppc-interrupt-server#s" or
 *       "ibm,ppc-interrupt-gserver#s"
 * - R6: "priority" is a valid priority not in
 *       "ibm,plat-res-int-priorities"
 *
 * Output:
 * - R4: "flags":
 *       Bits 0-61: Reserved
 *       Bit 62: The value of Event Queue Generation Number (g) per
 *              the XIVE spec if "Debug" = 1
 *       Bit 63: The value of Unconditional Notify (n) per the XIVE spec
 * - R5: The logical real address of the start of the EQ
 * - R6: The power of 2 EQ size per "ibm,xive-eq-sizes"
 * - R7: The value of Event Queue Offset Counter per XIVE spec
 *       if "Debug" = 1, else 0
 *
 */

#define SPAPR_XIVE_END_DEBUG     PPC_BIT(63)

static target_ulong h_int_get_queue_config(PowerPCCPU *cpu,
                                           SpaprMachineState *spapr,
                                           target_ulong opcode,
                                           target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    target_ulong flags = args[0];
    target_ulong target = args[1];
    target_ulong priority = args[2];
    XiveEND *end;
    uint8_t end_blk;
    uint32_t end_idx;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags & ~SPAPR_XIVE_END_DEBUG) {
        return H_PARAMETER;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    if (spapr_xive_priority_is_reserved(priority)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: priority " TARGET_FMT_ld
                      " is reserved\n", priority);
        return H_P3;
    }

    /*
     * Validate that "target" is part of the list of threads allocated
     * to the partition. For that, find the END corresponding to the
     * target.
     */
    if (spapr_xive_target_to_end(target, priority, &end_blk, &end_idx)) {
        return H_P2;
    }

    assert(end_idx < xive->nr_ends);
    end = &xive->endt[end_idx];

    args[0] = 0;
    if (xive_end_is_notify(end)) {
        args[0] |= SPAPR_XIVE_END_ALWAYS_NOTIFY;
    }

    if (xive_end_is_enqueue(end)) {
        args[1] = (uint64_t) be32_to_cpu(end->w2 & 0x0fffffff) << 32
            | be32_to_cpu(end->w3);
        args[2] = xive_get_field32(END_W0_QSIZE, end->w0) + 12;
    } else {
        args[1] = 0;
        args[2] = 0;
    }

    /* TODO: do we need any locking on the END ? */
    if (flags & SPAPR_XIVE_END_DEBUG) {
        /* Load the event queue generation number into the return flags */
        args[0] |= (uint64_t)xive_get_field32(END_W1_GENERATION, end->w1) << 62;

        /* Load R7 with the event queue offset counter */
        args[3] = xive_get_field32(END_W1_PAGE_OFF, end->w1);
    } else {
        args[3] = 0;
    }

    return H_SUCCESS;
}

/*
 * The H_INT_SET_OS_REPORTING_LINE hcall() is used to set the
 * reporting cache line pair for the calling thread.  The reporting
 * cache lines will contain the OS interrupt context when the OS
 * issues a CI store byte to @TIMA+0xC10 to acknowledge the OS
 * interrupt. The reporting cache lines can be reset by inputting -1
 * in "reportingLine".  Issuing the CI store byte without reporting
 * cache lines registered will result in the data not being accessible
 * to the OS.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63: Reserved
 * - R5: "reportingLine": The logical real address of the reporting cache
 *       line pair
 *
 * Output:
 * - None
 */
static target_ulong h_int_set_os_reporting_line(PowerPCCPU *cpu,
                                                SpaprMachineState *spapr,
                                                target_ulong opcode,
                                                target_ulong *args)
{
    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    /* TODO: H_INT_SET_OS_REPORTING_LINE */
    return H_FUNCTION;
}

/*
 * The H_INT_GET_OS_REPORTING_LINE hcall() is used to get the logical
 * real address of the reporting cache line pair set for the input
 * "target".  If no reporting cache line pair has been set, -1 is
 * returned.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63: Reserved
 * - R5: "target" is per "ibm,ppc-interrupt-server#s" or
 *       "ibm,ppc-interrupt-gserver#s"
 * - R6: "reportingLine": The logical real address of the reporting
 *        cache line pair
 *
 * Output:
 * - R4: The logical real address of the reporting line if set, else -1
 */
static target_ulong h_int_get_os_reporting_line(PowerPCCPU *cpu,
                                                SpaprMachineState *spapr,
                                                target_ulong opcode,
                                                target_ulong *args)
{
    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    /* TODO: H_INT_GET_OS_REPORTING_LINE */
    return H_FUNCTION;
}

/*
 * The H_INT_ESB hcall() is used to issue a load or store to the ESB
 * page for the input "lisn".  This hcall is only supported for LISNs
 * that have the ESB hcall flag set to 1 when returned from hcall()
 * H_INT_GET_SOURCE_INFO.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-62: Reserved
 *         bit 63: Store: Store=1, store operation, else load operation
 * - R5: "lisn" is per "interrupts", "interrupt-map", or
 *       "ibm,xive-lisn-ranges" properties, or as returned by the
 *       ibm,query-interrupt-source-number RTAS call, or as
 *       returned by the H_ALLOCATE_VAS_WINDOW hcall
 * - R6: "esbOffset" is the offset into the ESB page for the load or
 *       store operation
 * - R7: "storeData" is the data to write for a store operation
 *
 * Output:
 * - R4: The value of the load if load operation, else -1
 */

#define SPAPR_XIVE_ESB_STORE PPC_BIT(63)

static target_ulong h_int_esb(PowerPCCPU *cpu,
                              SpaprMachineState *spapr,
                              target_ulong opcode,
                              target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    XiveEAS eas;
    target_ulong flags  = args[0];
    target_ulong lisn   = args[1];
    target_ulong offset = args[2];
    target_ulong data   = args[3];
    hwaddr mmio_addr;
    XiveSource *xsrc = &xive->source;

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags & ~SPAPR_XIVE_ESB_STORE) {
        return H_PARAMETER;
    }

    if (lisn >= xive->nr_irqs) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Unknown LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    eas = xive->eat[lisn];
    if (!xive_eas_is_valid(&eas)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Invalid LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    if (offset > (1ull << xsrc->esb_shift)) {
        return H_P3;
    }

    mmio_addr = xive->vc_base + xive_source_esb_mgmt(xsrc, lisn) + offset;

    if (dma_memory_rw(&address_space_memory, mmio_addr, &data, 8,
                      (flags & SPAPR_XIVE_ESB_STORE))) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: failed to access ESB @0x%"
                      HWADDR_PRIx "\n", mmio_addr);
        return H_HARDWARE;
    }
    args[0] = (flags & SPAPR_XIVE_ESB_STORE) ? -1 : data;
    return H_SUCCESS;
}

/*
 * The H_INT_SYNC hcall() is used to issue hardware syncs that will
 * ensure any in flight events for the input lisn are in the event
 * queue.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63: Reserved
 * - R5: "lisn" is per "interrupts", "interrupt-map", or
 *       "ibm,xive-lisn-ranges" properties, or as returned by the
 *       ibm,query-interrupt-source-number RTAS call, or as
 *       returned by the H_ALLOCATE_VAS_WINDOW hcall
 *
 * Output:
 * - None
 */
static target_ulong h_int_sync(PowerPCCPU *cpu,
                               SpaprMachineState *spapr,
                               target_ulong opcode,
                               target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    XiveEAS eas;
    target_ulong flags = args[0];
    target_ulong lisn = args[1];

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags) {
        return H_PARAMETER;
    }

    if (lisn >= xive->nr_irqs) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Unknown LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    eas = xive->eat[lisn];
    if (!xive_eas_is_valid(&eas)) {
        qemu_log_mask(LOG_GUEST_ERROR, "XIVE: Invalid LISN " TARGET_FMT_lx "\n",
                      lisn);
        return H_P2;
    }

    /*
     * H_STATE should be returned if a H_INT_RESET is in progress.
     * This is not needed when running the emulation under QEMU
     */

    /* This is not real hardware. Nothing to be done */
    return H_SUCCESS;
}

/*
 * The H_INT_RESET hcall() is used to reset all of the partition's
 * interrupt exploitation structures to their initial state.  This
 * means losing all previously set interrupt state set via
 * H_INT_SET_SOURCE_CONFIG and H_INT_SET_QUEUE_CONFIG.
 *
 * Parameters:
 * Input:
 * - R4: "flags"
 *         Bits 0-63: Reserved
 *
 * Output:
 * - None
 */
static target_ulong h_int_reset(PowerPCCPU *cpu,
                                SpaprMachineState *spapr,
                                target_ulong opcode,
                                target_ulong *args)
{
    SpaprXive *xive = spapr->xive;
    target_ulong flags   = args[0];

    if (!spapr_ovec_test(spapr->ov5_cas, OV5_XIVE_EXPLOIT)) {
        return H_FUNCTION;
    }

    if (flags) {
        return H_PARAMETER;
    }

    device_reset(DEVICE(xive));
    return H_SUCCESS;
}

void spapr_xive_hcall_init(SpaprMachineState *spapr)
{
    spapr_register_hypercall(H_INT_GET_SOURCE_INFO, h_int_get_source_info);
    spapr_register_hypercall(H_INT_SET_SOURCE_CONFIG, h_int_set_source_config);
    spapr_register_hypercall(H_INT_GET_SOURCE_CONFIG, h_int_get_source_config);
    spapr_register_hypercall(H_INT_GET_QUEUE_INFO, h_int_get_queue_info);
    spapr_register_hypercall(H_INT_SET_QUEUE_CONFIG, h_int_set_queue_config);
    spapr_register_hypercall(H_INT_GET_QUEUE_CONFIG, h_int_get_queue_config);
    spapr_register_hypercall(H_INT_SET_OS_REPORTING_LINE,
                             h_int_set_os_reporting_line);
    spapr_register_hypercall(H_INT_GET_OS_REPORTING_LINE,
                             h_int_get_os_reporting_line);
    spapr_register_hypercall(H_INT_ESB, h_int_esb);
    spapr_register_hypercall(H_INT_SYNC, h_int_sync);
    spapr_register_hypercall(H_INT_RESET, h_int_reset);
}

void spapr_dt_xive(SpaprMachineState *spapr, uint32_t nr_servers, void *fdt,
                   uint32_t phandle)
{
    SpaprXive *xive = spapr->xive;
    int node;
    uint64_t timas[2 * 2];
    /* Interrupt number ranges for the IPIs */
    uint32_t lisn_ranges[] = {
        cpu_to_be32(0),
        cpu_to_be32(nr_servers),
    };
    /*
     * EQ size - the sizes of pages supported by the system 4K, 64K,
     * 2M, 16M. We only advertise 64K for the moment.
     */
    uint32_t eq_sizes[] = {
        cpu_to_be32(16), /* 64K */
    };
    /*
     * The following array is in sync with the reserved priorities
     * defined by the 'spapr_xive_priority_is_reserved' routine.
     */
    uint32_t plat_res_int_priorities[] = {
        cpu_to_be32(7),    /* start */
        cpu_to_be32(0xf8), /* count */
    };

    /* Thread Interrupt Management Area : User (ring 3) and OS (ring 2) */
    timas[0] = cpu_to_be64(xive->tm_base +
                           XIVE_TM_USER_PAGE * (1ull << TM_SHIFT));
    timas[1] = cpu_to_be64(1ull << TM_SHIFT);
    timas[2] = cpu_to_be64(xive->tm_base +
                           XIVE_TM_OS_PAGE * (1ull << TM_SHIFT));
    timas[3] = cpu_to_be64(1ull << TM_SHIFT);

    _FDT(node = fdt_add_subnode(fdt, 0, xive->nodename));

    _FDT(fdt_setprop_string(fdt, node, "device_type", "power-ivpe"));
    _FDT(fdt_setprop(fdt, node, "reg", timas, sizeof(timas)));

    _FDT(fdt_setprop_string(fdt, node, "compatible", "ibm,power-ivpe"));
    _FDT(fdt_setprop(fdt, node, "ibm,xive-eq-sizes", eq_sizes,
                     sizeof(eq_sizes)));
    _FDT(fdt_setprop(fdt, node, "ibm,xive-lisn-ranges", lisn_ranges,
                     sizeof(lisn_ranges)));

    /* For Linux to link the LSIs to the interrupt controller. */
    _FDT(fdt_setprop(fdt, node, "interrupt-controller", NULL, 0));
    _FDT(fdt_setprop_cell(fdt, node, "#interrupt-cells", 2));

    /* For SLOF */
    _FDT(fdt_setprop_cell(fdt, node, "linux,phandle", phandle));
    _FDT(fdt_setprop_cell(fdt, node, "phandle", phandle));

    /*
     * The "ibm,plat-res-int-priorities" property defines the priority
     * ranges reserved by the hypervisor
     */
    _FDT(fdt_setprop(fdt, 0, "ibm,plat-res-int-priorities",
                     plat_res_int_priorities, sizeof(plat_res_int_priorities)));
}

/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtualized Interrupt System, aka ICS/ICP aka xics
 *
 * Copyright (c) 2010,2011 David Gibson, IBM Corporation.
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
 */

#ifndef XICS_H
#define XICS_H

#include "hw/qdev.h"

#define XICS_IPI        0x2
#define XICS_BUID       0x1
#define XICS_IRQ_BASE   (XICS_BUID << 12)

/*
 * We currently only support one BUID which is our interrupt base
 * (the kernel implementation supports more but we don't exploit
 *  that yet)
 */
typedef struct ICPStateClass ICPStateClass;
typedef struct ICPState ICPState;
typedef struct PnvICPState PnvICPState;
typedef struct ICSStateClass ICSStateClass;
typedef struct ICSState ICSState;
typedef struct ICSIRQState ICSIRQState;
typedef struct XICSFabric XICSFabric;

#define TYPE_ICP "icp"
#define ICP(obj) OBJECT_CHECK(ICPState, (obj), TYPE_ICP)

#define TYPE_PNV_ICP "pnv-icp"
#define PNV_ICP(obj) OBJECT_CHECK(PnvICPState, (obj), TYPE_PNV_ICP)

#define ICP_CLASS(klass) \
     OBJECT_CLASS_CHECK(ICPStateClass, (klass), TYPE_ICP)
#define ICP_GET_CLASS(obj) \
     OBJECT_GET_CLASS(ICPStateClass, (obj), TYPE_ICP)

struct ICPStateClass {
    DeviceClass parent_class;

    DeviceRealize parent_realize;
};

struct ICPState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/
    CPUState *cs;
    ICSState *xirr_owner;
    uint32_t xirr;
    uint8_t pending_priority;
    uint8_t mfrr;
    qemu_irq output;

    XICSFabric *xics;
};

#define ICP_PROP_XICS "xics"
#define ICP_PROP_CPU "cpu"

struct PnvICPState {
    ICPState parent_obj;

    MemoryRegion mmio;
    uint32_t links[3];
};

#define TYPE_ICS_BASE "ics-base"
#define ICS_BASE(obj) OBJECT_CHECK(ICSState, (obj), TYPE_ICS_BASE)

/* Retain ics for sPAPR for migration from existing sPAPR guests */
#define TYPE_ICS_SIMPLE "ics"
#define ICS_SIMPLE(obj) OBJECT_CHECK(ICSState, (obj), TYPE_ICS_SIMPLE)

#define ICS_BASE_CLASS(klass) \
     OBJECT_CLASS_CHECK(ICSStateClass, (klass), TYPE_ICS_BASE)
#define ICS_BASE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(ICSStateClass, (obj), TYPE_ICS_BASE)

struct ICSStateClass {
    DeviceClass parent_class;

    DeviceRealize parent_realize;
    DeviceReset parent_reset;

    void (*reject)(ICSState *s, uint32_t irq);
    void (*resend)(ICSState *s);
    void (*eoi)(ICSState *s, uint32_t irq);
};

struct ICSState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/
    uint32_t nr_irqs;
    uint32_t offset;
    ICSIRQState *irqs;
    XICSFabric *xics;
};

#define ICS_PROP_XICS "xics"

static inline bool ics_valid_irq(ICSState *ics, uint32_t nr)
{
    return (nr >= ics->offset) && (nr < (ics->offset + ics->nr_irqs));
}

struct ICSIRQState {
    uint32_t server;
    uint8_t priority;
    uint8_t saved_priority;
#define XICS_STATUS_ASSERTED           0x1
#define XICS_STATUS_SENT               0x2
#define XICS_STATUS_REJECTED           0x4
#define XICS_STATUS_MASKED_PENDING     0x8
#define XICS_STATUS_PRESENTED          0x10
#define XICS_STATUS_QUEUED             0x20
    uint8_t status;
/* (flags & XICS_FLAGS_IRQ_MASK) == 0 means the interrupt is not allocated */
#define XICS_FLAGS_IRQ_LSI             0x1
#define XICS_FLAGS_IRQ_MSI             0x2
#define XICS_FLAGS_IRQ_MASK            0x3
    uint8_t flags;
};

struct XICSFabric {
    Object parent;
};

#define TYPE_XICS_FABRIC "xics-fabric"
#define XICS_FABRIC(obj)                                     \
    OBJECT_CHECK(XICSFabric, (obj), TYPE_XICS_FABRIC)
#define XICS_FABRIC_CLASS(klass)                                     \
    OBJECT_CLASS_CHECK(XICSFabricClass, (klass), TYPE_XICS_FABRIC)
#define XICS_FABRIC_GET_CLASS(obj)                                   \
    OBJECT_GET_CLASS(XICSFabricClass, (obj), TYPE_XICS_FABRIC)

typedef struct XICSFabricClass {
    InterfaceClass parent;
    ICSState *(*ics_get)(XICSFabric *xi, int irq);
    void (*ics_resend)(XICSFabric *xi);
    ICPState *(*icp_get)(XICSFabric *xi, int server);
} XICSFabricClass;

ICPState *xics_icp_get(XICSFabric *xi, int server);

/* Internal XICS interfaces */
void icp_set_cppr(ICPState *icp, uint8_t cppr);
void icp_set_mfrr(ICPState *icp, uint8_t mfrr);
uint32_t icp_accept(ICPState *ss);
uint32_t icp_ipoll(ICPState *ss, uint32_t *mfrr);
void icp_eoi(ICPState *icp, uint32_t xirr);

void ics_simple_write_xive(ICSState *ics, int nr, int server,
                           uint8_t priority, uint8_t saved_priority);
void ics_simple_set_irq(void *opaque, int srcno, int val);

void ics_set_irq_type(ICSState *ics, int srcno, bool lsi);
void icp_pic_print_info(ICPState *icp, Monitor *mon);
void ics_pic_print_info(ICSState *ics, Monitor *mon);

void ics_resend(ICSState *ics);
void icp_resend(ICPState *ss);

Object *icp_create(Object *cpu, const char *type, XICSFabric *xi,
                   Error **errp);

/* KVM */
void icp_get_kvm_state(ICPState *icp);
int icp_set_kvm_state(ICPState *icp);
void icp_synchronize_state(ICPState *icp);
void icp_kvm_realize(DeviceState *dev, Error **errp);

void ics_get_kvm_state(ICSState *ics);
int ics_set_kvm_state_one(ICSState *ics, int srcno);
int ics_set_kvm_state(ICSState *ics);
void ics_synchronize_state(ICSState *ics);
void ics_kvm_set_irq(ICSState *ics, int srcno, int val);

#endif /* XICS_H */

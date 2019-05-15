/*
 * s390 PCI instruction definitions
 *
 * Copyright 2014 IBM Corp.
 * Author(s): Frank Blaschka <frank.blaschka@de.ibm.com>
 *            Hong Bo Li <lihbbj@cn.ibm.com>
 *            Yi Min Zhao <zyimin@cn.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#ifndef HW_S390_PCI_INST_H
#define HW_S390_PCI_INST_H

#include "s390-pci-bus.h"
#include "sysemu/dma.h"

/* CLP common request & response block size */
#define CLP_BLK_SIZE 4096
#define PCI_BAR_COUNT 6
#define PCI_MAX_FUNCTIONS 4096

typedef struct ClpReqHdr {
    uint16_t len;
    uint16_t cmd;
} QEMU_PACKED ClpReqHdr;

typedef struct ClpRspHdr {
    uint16_t len;
    uint16_t rsp;
} QEMU_PACKED ClpRspHdr;

/* CLP Response Codes */
#define CLP_RC_OK         0x0010  /* Command request successfully */
#define CLP_RC_CMD        0x0020  /* Command code not recognized */
#define CLP_RC_PERM       0x0030  /* Command not authorized */
#define CLP_RC_FMT        0x0040  /* Invalid command request format */
#define CLP_RC_LEN        0x0050  /* Invalid command request length */
#define CLP_RC_8K         0x0060  /* Command requires 8K LPCB */
#define CLP_RC_RESNOT0    0x0070  /* Reserved field not zero */
#define CLP_RC_NODATA     0x0080  /* No data available */
#define CLP_RC_FC_UNKNOWN 0x0100  /* Function code not recognized */

/*
 * Call Logical Processor - Command Codes
 */
#define CLP_LIST_PCI            0x0002
#define CLP_QUERY_PCI_FN        0x0003
#define CLP_QUERY_PCI_FNGRP     0x0004
#define CLP_SET_PCI_FN          0x0005

/* PCI function handle list entry */
typedef struct ClpFhListEntry {
    uint16_t device_id;
    uint16_t vendor_id;
#define CLP_FHLIST_MASK_CONFIG 0x80000000
    uint32_t config;
    uint32_t fid;
    uint32_t fh;
} QEMU_PACKED ClpFhListEntry;

#define CLP_RC_SETPCIFN_FH      0x0101 /* Invalid PCI fn handle */
#define CLP_RC_SETPCIFN_FHOP    0x0102 /* Fn handle not valid for op */
#define CLP_RC_SETPCIFN_DMAAS   0x0103 /* Invalid DMA addr space */
#define CLP_RC_SETPCIFN_RES     0x0104 /* Insufficient resources */
#define CLP_RC_SETPCIFN_ALRDY   0x0105 /* Fn already in requested state */
#define CLP_RC_SETPCIFN_ERR     0x0106 /* Fn in permanent error state */
#define CLP_RC_SETPCIFN_RECPND  0x0107 /* Error recovery pending */
#define CLP_RC_SETPCIFN_BUSY    0x0108 /* Fn busy */
#define CLP_RC_LISTPCI_BADRT    0x010a /* Resume token not recognized */
#define CLP_RC_QUERYPCIFG_PFGID 0x010b /* Unrecognized PFGID */

/* request or response block header length */
#define LIST_PCI_HDR_LEN 32

/* Number of function handles fitting in response block */
#define CLP_FH_LIST_NR_ENTRIES \
    ((CLP_BLK_SIZE - 2 * LIST_PCI_HDR_LEN) \
        / sizeof(ClpFhListEntry))

#define CLP_SET_ENABLE_PCI_FN  0 /* Yes, 0 enables it */
#define CLP_SET_DISABLE_PCI_FN 1 /* Yes, 1 disables it */

#define CLP_UTIL_STR_LEN 64

#define CLP_MASK_FMT 0xf0000000

/* List PCI functions request */
typedef struct ClpReqListPci {
    ClpReqHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint64_t resume_token;
    uint64_t reserved2;
} QEMU_PACKED ClpReqListPci;

/* List PCI functions response */
typedef struct ClpRspListPci {
    ClpRspHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint64_t resume_token;
    uint32_t mdd;
    uint16_t max_fn;
    uint8_t flags;
    uint8_t entry_size;
    ClpFhListEntry fh_list[CLP_FH_LIST_NR_ENTRIES];
} QEMU_PACKED ClpRspListPci;

/* Query PCI function request */
typedef struct ClpReqQueryPci {
    ClpReqHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint32_t fh; /* function handle */
    uint32_t reserved2;
    uint64_t reserved3;
} QEMU_PACKED ClpReqQueryPci;

/* Query PCI function response */
typedef struct ClpRspQueryPci {
    ClpRspHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint16_t vfn; /* virtual fn number */
#define CLP_RSP_QPCI_MASK_UTIL  0x100
#define CLP_RSP_QPCI_MASK_PFGID 0xff
    uint16_t ug;
    uint32_t fid; /* pci function id */
    uint8_t bar_size[PCI_BAR_COUNT];
    uint16_t pchid;
    uint32_t bar[PCI_BAR_COUNT];
    uint64_t reserved2;
    uint64_t sdma; /* start dma as */
    uint64_t edma; /* end dma as */
    uint32_t reserved3[11];
    uint32_t uid;
    uint8_t util_str[CLP_UTIL_STR_LEN]; /* utility string */
} QEMU_PACKED ClpRspQueryPci;

/* Query PCI function group request */
typedef struct ClpReqQueryPciGrp {
    ClpReqHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
#define CLP_REQ_QPCIG_MASK_PFGID 0xff
    uint32_t g;
    uint32_t reserved2;
    uint64_t reserved3;
} QEMU_PACKED ClpReqQueryPciGrp;

/* Query PCI function group response */
typedef struct ClpRspQueryPciGrp {
    ClpRspHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
#define CLP_RSP_QPCIG_MASK_NOI 0xfff
    uint16_t i;
    uint8_t version;
#define CLP_RSP_QPCIG_MASK_FRAME   0x2
#define CLP_RSP_QPCIG_MASK_REFRESH 0x1
    uint8_t fr;
    uint16_t maxstbl;
    uint16_t mui;
    uint64_t reserved3;
    uint64_t dasm; /* dma address space mask */
    uint64_t msia; /* MSI address */
    uint64_t reserved4;
    uint64_t reserved5;
} QEMU_PACKED ClpRspQueryPciGrp;

/* Set PCI function request */
typedef struct ClpReqSetPci {
    ClpReqHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint32_t fh; /* function handle */
    uint16_t reserved2;
    uint8_t oc; /* operation controls */
    uint8_t ndas; /* number of dma spaces */
    uint64_t reserved3;
} QEMU_PACKED ClpReqSetPci;

/* Set PCI function response */
typedef struct ClpRspSetPci {
    ClpRspHdr hdr;
    uint32_t fmt;
    uint64_t reserved1;
    uint32_t fh; /* function handle */
    uint32_t reserved3;
    uint64_t reserved4;
} QEMU_PACKED ClpRspSetPci;

typedef struct ClpReqRspListPci {
    ClpReqListPci request;
    ClpRspListPci response;
} QEMU_PACKED ClpReqRspListPci;

typedef struct ClpReqRspSetPci {
    ClpReqSetPci request;
    ClpRspSetPci response;
} QEMU_PACKED ClpReqRspSetPci;

typedef struct ClpReqRspQueryPci {
    ClpReqQueryPci request;
    ClpRspQueryPci response;
} QEMU_PACKED ClpReqRspQueryPci;

typedef struct ClpReqRspQueryPciGrp {
    ClpReqQueryPciGrp request;
    ClpRspQueryPciGrp response;
} QEMU_PACKED ClpReqRspQueryPciGrp;

/* Load/Store status codes */
#define ZPCI_PCI_ST_FUNC_NOT_ENABLED        4
#define ZPCI_PCI_ST_FUNC_IN_ERR             8
#define ZPCI_PCI_ST_BLOCKED                 12
#define ZPCI_PCI_ST_INSUF_RES               16
#define ZPCI_PCI_ST_INVAL_AS                20
#define ZPCI_PCI_ST_FUNC_ALREADY_ENABLED    24
#define ZPCI_PCI_ST_DMA_AS_NOT_ENABLED      28
#define ZPCI_PCI_ST_2ND_OP_IN_INV_AS        36
#define ZPCI_PCI_ST_FUNC_NOT_AVAIL          40
#define ZPCI_PCI_ST_ALREADY_IN_RQ_STATE     44

/* Load/Store return codes */
#define ZPCI_PCI_LS_OK              0
#define ZPCI_PCI_LS_ERR             1
#define ZPCI_PCI_LS_BUSY            2
#define ZPCI_PCI_LS_INVAL_HANDLE    3

/* Modify PCI status codes */
#define ZPCI_MOD_ST_RES_NOT_AVAIL 4
#define ZPCI_MOD_ST_INSUF_RES     16
#define ZPCI_MOD_ST_SEQUENCE      24
#define ZPCI_MOD_ST_DMAAS_INVAL   28
#define ZPCI_MOD_ST_FRAME_INVAL   32
#define ZPCI_MOD_ST_ERROR_RECOVER 40

/* Modify PCI Function Controls */
#define ZPCI_MOD_FC_REG_INT     2
#define ZPCI_MOD_FC_DEREG_INT   3
#define ZPCI_MOD_FC_REG_IOAT    4
#define ZPCI_MOD_FC_DEREG_IOAT  5
#define ZPCI_MOD_FC_REREG_IOAT  6
#define ZPCI_MOD_FC_RESET_ERROR 7
#define ZPCI_MOD_FC_RESET_BLOCK 9
#define ZPCI_MOD_FC_SET_MEASURE 10

/* Store PCI Function Controls status codes */
#define ZPCI_STPCIFC_ST_PERM_ERROR    8
#define ZPCI_STPCIFC_ST_INVAL_DMAAS   28
#define ZPCI_STPCIFC_ST_ERROR_RECOVER 40

/* FIB function controls */
#define ZPCI_FIB_FC_ENABLED     0x80
#define ZPCI_FIB_FC_ERROR       0x40
#define ZPCI_FIB_FC_LS_BLOCKED  0x20
#define ZPCI_FIB_FC_DMAAS_REG   0x10

/* FIB function controls */
#define ZPCI_FIB_FC_ENABLED     0x80
#define ZPCI_FIB_FC_ERROR       0x40
#define ZPCI_FIB_FC_LS_BLOCKED  0x20
#define ZPCI_FIB_FC_DMAAS_REG   0x10

/* Function Information Block */
typedef struct ZpciFib {
    uint8_t fmt;   /* format */
    uint8_t reserved1[7];
    uint8_t fc;                  /* function controls */
    uint8_t reserved2;
    uint16_t reserved3;
    uint32_t reserved4;
    uint64_t pba;                /* PCI base address */
    uint64_t pal;                /* PCI address limit */
    uint64_t iota;               /* I/O Translation Anchor */
#define FIB_DATA_ISC(x)    (((x) >> 28) & 0x7)
#define FIB_DATA_NOI(x)    (((x) >> 16) & 0xfff)
#define FIB_DATA_AIBVO(x) (((x) >> 8) & 0x3f)
#define FIB_DATA_SUM(x)    (((x) >> 7) & 0x1)
#define FIB_DATA_AISBO(x)  ((x) & 0x3f)
    uint32_t data;
    uint32_t reserved5;
    uint64_t aibv;               /* Adapter int bit vector address */
    uint64_t aisb;               /* Adapter int summary bit address */
    uint64_t fmb_addr;           /* Function measurement address and key */
    uint32_t reserved6;
    uint32_t gd;
} QEMU_PACKED ZpciFib;

int pci_dereg_irqs(S390PCIBusDevice *pbdev);
void pci_dereg_ioat(S390PCIIOMMU *iommu);
int clp_service_call(S390CPU *cpu, uint8_t r2, uintptr_t ra);
int pcilg_service_call(S390CPU *cpu, uint8_t r1, uint8_t r2, uintptr_t ra);
int pcistg_service_call(S390CPU *cpu, uint8_t r1, uint8_t r2, uintptr_t ra);
int rpcit_service_call(S390CPU *cpu, uint8_t r1, uint8_t r2, uintptr_t ra);
int pcistb_service_call(S390CPU *cpu, uint8_t r1, uint8_t r3, uint64_t gaddr,
                        uint8_t ar, uintptr_t ra);
int mpcifc_service_call(S390CPU *cpu, uint8_t r1, uint64_t fiba, uint8_t ar,
                        uintptr_t ra);
int stpcifc_service_call(S390CPU *cpu, uint8_t r1, uint64_t fiba, uint8_t ar,
                         uintptr_t ra);
void fmb_timer_free(S390PCIBusDevice *pbdev);

#define ZPCI_IO_BAR_MIN 0
#define ZPCI_IO_BAR_MAX 5
#define ZPCI_CONFIG_BAR 15

#endif

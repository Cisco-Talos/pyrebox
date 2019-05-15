#ifndef HW_PCMCIA_H
#define HW_PCMCIA_H

/* PCMCIA/Cardbus */

#include "hw/qdev.h"

typedef struct PCMCIASocket {
    qemu_irq irq;
    bool attached;
} PCMCIASocket;

#define TYPE_PCMCIA_CARD "pcmcia-card"
#define PCMCIA_CARD(obj) \
    OBJECT_CHECK(PCMCIACardState, (obj), TYPE_PCMCIA_CARD)
#define PCMCIA_CARD_GET_CLASS(obj) \
    OBJECT_GET_CLASS(PCMCIACardClass, obj, TYPE_PCMCIA_CARD)
#define PCMCIA_CARD_CLASS(cls) \
    OBJECT_CLASS_CHECK(PCMCIACardClass, cls, TYPE_PCMCIA_CARD)

typedef struct PCMCIACardState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/

    PCMCIASocket *slot;
} PCMCIACardState;

typedef struct PCMCIACardClass {
    /*< private >*/
    DeviceClass parent_class;
    /*< public >*/

    int (*attach)(PCMCIACardState *state);
    int (*detach)(PCMCIACardState *state);

    const uint8_t *cis;
    int cis_len;

    /* Only valid if attached */
    uint8_t (*attr_read)(PCMCIACardState *card, uint32_t address);
    void (*attr_write)(PCMCIACardState *card, uint32_t address, uint8_t value);
    uint16_t (*common_read)(PCMCIACardState *card, uint32_t address);
    void (*common_write)(PCMCIACardState *card,
                         uint32_t address, uint16_t value);
    uint16_t (*io_read)(PCMCIACardState *card, uint32_t address);
    void (*io_write)(PCMCIACardState *card, uint32_t address, uint16_t value);
} PCMCIACardClass;

#define CISTPL_DEVICE		0x01	/* 5V Device Information Tuple */
#define CISTPL_NO_LINK		0x14	/* No Link Tuple */
#define CISTPL_VERS_1		0x15	/* Level 1 Version Tuple */
#define CISTPL_JEDEC_C		0x18	/* JEDEC ID Tuple */
#define CISTPL_JEDEC_A		0x19	/* JEDEC ID Tuple */
#define CISTPL_CONFIG		0x1a	/* Configuration Tuple */
#define CISTPL_CFTABLE_ENTRY	0x1b	/* 16-bit PCCard Configuration */
#define CISTPL_DEVICE_OC	0x1c	/* Additional Device Information */
#define CISTPL_DEVICE_OA	0x1d	/* Additional Device Information */
#define CISTPL_DEVICE_GEO	0x1e	/* Additional Device Information */
#define CISTPL_DEVICE_GEO_A	0x1f	/* Additional Device Information */
#define CISTPL_MANFID		0x20	/* Manufacture ID Tuple */
#define CISTPL_FUNCID		0x21	/* Function ID Tuple */
#define CISTPL_FUNCE		0x22	/* Function Extension Tuple */
#define CISTPL_END		0xff	/* Tuple End */
#define CISTPL_ENDMARK		0xff

/* dscm1xxxx.c */
PCMCIACardState *dscm1xxxx_init(DriveInfo *bdrv);

#endif

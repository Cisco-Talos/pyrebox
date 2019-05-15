/*
 * QEMU SM501 Device
 *
 * Copyright (c) 2008 Shin-ichiro KAWASAKI
 * Copyright (c) 2016 BALATON Zoltan
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
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/char/serial.h"
#include "ui/console.h"
#include "hw/sysbus.h"
#include "hw/pci/pci.h"
#include "hw/i2c/i2c.h"
#include "hw/i2c/i2c-ddc.h"
#include "qemu/range.h"
#include "ui/pixel_ops.h"
#include "qemu/bswap.h"

/*
 * Status: 2010/05/07
 *   - Minimum implementation for Linux console : mmio regs and CRT layer.
 *   - 2D graphics acceleration partially supported : only fill rectangle.
 *
 * Status: 2016/12/04
 *   - Misc fixes: endianness, hardware cursor
 *   - Panel support
 *
 * TODO:
 *   - Touch panel support
 *   - USB support
 *   - UART support
 *   - More 2D graphics engine support
 *   - Performance tuning
 */

/*#define DEBUG_SM501*/
/*#define DEBUG_BITBLT*/

#ifdef DEBUG_SM501
#define SM501_DPRINTF(fmt, ...) printf(fmt, ## __VA_ARGS__)
#else
#define SM501_DPRINTF(fmt, ...) do {} while (0)
#endif

#define MMIO_BASE_OFFSET 0x3e00000
#define MMIO_SIZE 0x200000
#define DC_PALETTE_ENTRIES (0x400 * 3)

/* SM501 register definitions taken from "linux/include/linux/sm501-regs.h" */

/* System Configuration area */
/* System config base */
#define SM501_SYS_CONFIG                (0x000000)

/* config 1 */
#define SM501_SYSTEM_CONTROL            (0x000000)

#define SM501_SYSCTRL_PANEL_TRISTATE    (1 << 0)
#define SM501_SYSCTRL_MEM_TRISTATE      (1 << 1)
#define SM501_SYSCTRL_CRT_TRISTATE      (1 << 2)

#define SM501_SYSCTRL_PCI_SLAVE_BURST_MASK (3 << 4)
#define SM501_SYSCTRL_PCI_SLAVE_BURST_1 (0 << 4)
#define SM501_SYSCTRL_PCI_SLAVE_BURST_2 (1 << 4)
#define SM501_SYSCTRL_PCI_SLAVE_BURST_4 (2 << 4)
#define SM501_SYSCTRL_PCI_SLAVE_BURST_8 (3 << 4)

#define SM501_SYSCTRL_PCI_CLOCK_RUN_EN  (1 << 6)
#define SM501_SYSCTRL_PCI_RETRY_DISABLE (1 << 7)
#define SM501_SYSCTRL_PCI_SUBSYS_LOCK   (1 << 11)
#define SM501_SYSCTRL_PCI_BURST_READ_EN (1 << 15)

/* miscellaneous control */

#define SM501_MISC_CONTROL              (0x000004)

#define SM501_MISC_BUS_SH               (0x0)
#define SM501_MISC_BUS_PCI              (0x1)
#define SM501_MISC_BUS_XSCALE           (0x2)
#define SM501_MISC_BUS_NEC              (0x6)
#define SM501_MISC_BUS_MASK             (0x7)

#define SM501_MISC_VR_62MB              (1 << 3)
#define SM501_MISC_CDR_RESET            (1 << 7)
#define SM501_MISC_USB_LB               (1 << 8)
#define SM501_MISC_USB_SLAVE            (1 << 9)
#define SM501_MISC_BL_1                 (1 << 10)
#define SM501_MISC_MC                   (1 << 11)
#define SM501_MISC_DAC_POWER            (1 << 12)
#define SM501_MISC_IRQ_INVERT           (1 << 16)
#define SM501_MISC_SH                   (1 << 17)

#define SM501_MISC_HOLD_EMPTY           (0 << 18)
#define SM501_MISC_HOLD_8               (1 << 18)
#define SM501_MISC_HOLD_16              (2 << 18)
#define SM501_MISC_HOLD_24              (3 << 18)
#define SM501_MISC_HOLD_32              (4 << 18)
#define SM501_MISC_HOLD_MASK            (7 << 18)

#define SM501_MISC_FREQ_12              (1 << 24)
#define SM501_MISC_PNL_24BIT            (1 << 25)
#define SM501_MISC_8051_LE              (1 << 26)



#define SM501_GPIO31_0_CONTROL          (0x000008)
#define SM501_GPIO63_32_CONTROL         (0x00000C)
#define SM501_DRAM_CONTROL              (0x000010)

/* command list */
#define SM501_ARBTRTN_CONTROL           (0x000014)

/* command list */
#define SM501_COMMAND_LIST_STATUS       (0x000024)

/* interrupt debug */
#define SM501_RAW_IRQ_STATUS            (0x000028)
#define SM501_RAW_IRQ_CLEAR             (0x000028)
#define SM501_IRQ_STATUS                (0x00002C)
#define SM501_IRQ_MASK                  (0x000030)
#define SM501_DEBUG_CONTROL             (0x000034)

/* power management */
#define SM501_POWERMODE_P2X_SRC         (1 << 29)
#define SM501_POWERMODE_V2X_SRC         (1 << 20)
#define SM501_POWERMODE_M_SRC           (1 << 12)
#define SM501_POWERMODE_M1_SRC          (1 << 4)

#define SM501_CURRENT_GATE              (0x000038)
#define SM501_CURRENT_CLOCK             (0x00003C)
#define SM501_POWER_MODE_0_GATE         (0x000040)
#define SM501_POWER_MODE_0_CLOCK        (0x000044)
#define SM501_POWER_MODE_1_GATE         (0x000048)
#define SM501_POWER_MODE_1_CLOCK        (0x00004C)
#define SM501_SLEEP_MODE_GATE           (0x000050)
#define SM501_POWER_MODE_CONTROL        (0x000054)

/* power gates for units within the 501 */
#define SM501_GATE_HOST                 (0)
#define SM501_GATE_MEMORY               (1)
#define SM501_GATE_DISPLAY              (2)
#define SM501_GATE_2D_ENGINE            (3)
#define SM501_GATE_CSC                  (4)
#define SM501_GATE_ZVPORT               (5)
#define SM501_GATE_GPIO                 (6)
#define SM501_GATE_UART0                (7)
#define SM501_GATE_UART1                (8)
#define SM501_GATE_SSP                  (10)
#define SM501_GATE_USB_HOST             (11)
#define SM501_GATE_USB_GADGET           (12)
#define SM501_GATE_UCONTROLLER          (17)
#define SM501_GATE_AC97                 (18)

/* panel clock */
#define SM501_CLOCK_P2XCLK              (24)
/* crt clock */
#define SM501_CLOCK_V2XCLK              (16)
/* main clock */
#define SM501_CLOCK_MCLK                (8)
/* SDRAM controller clock */
#define SM501_CLOCK_M1XCLK              (0)

/* config 2 */
#define SM501_PCI_MASTER_BASE           (0x000058)
#define SM501_ENDIAN_CONTROL            (0x00005C)
#define SM501_DEVICEID                  (0x000060)
/* 0x050100A0 */

#define SM501_DEVICEID_SM501            (0x05010000)
#define SM501_DEVICEID_IDMASK           (0xffff0000)
#define SM501_DEVICEID_REVMASK          (0x000000ff)

#define SM501_PLLCLOCK_COUNT            (0x000064)
#define SM501_MISC_TIMING               (0x000068)
#define SM501_CURRENT_SDRAM_CLOCK       (0x00006C)

#define SM501_PROGRAMMABLE_PLL_CONTROL  (0x000074)

/* GPIO base */
#define SM501_GPIO                      (0x010000)
#define SM501_GPIO_DATA_LOW             (0x00)
#define SM501_GPIO_DATA_HIGH            (0x04)
#define SM501_GPIO_DDR_LOW              (0x08)
#define SM501_GPIO_DDR_HIGH             (0x0C)
#define SM501_GPIO_IRQ_SETUP            (0x10)
#define SM501_GPIO_IRQ_STATUS           (0x14)
#define SM501_GPIO_IRQ_RESET            (0x14)

/* I2C controller base */
#define SM501_I2C                       (0x010040)
#define SM501_I2C_BYTE_COUNT            (0x00)
#define SM501_I2C_CONTROL               (0x01)
#define SM501_I2C_STATUS                (0x02)
#define SM501_I2C_RESET                 (0x02)
#define SM501_I2C_SLAVE_ADDRESS         (0x03)
#define SM501_I2C_DATA                  (0x04)

#define SM501_I2C_CONTROL_START         (1 << 2)
#define SM501_I2C_CONTROL_ENABLE        (1 << 0)

#define SM501_I2C_STATUS_COMPLETE       (1 << 3)
#define SM501_I2C_STATUS_ERROR          (1 << 2)

#define SM501_I2C_RESET_ERROR           (1 << 2)

/* SSP base */
#define SM501_SSP                       (0x020000)

/* Uart 0 base */
#define SM501_UART0                     (0x030000)

/* Uart 1 base */
#define SM501_UART1                     (0x030020)

/* USB host port base */
#define SM501_USB_HOST                  (0x040000)

/* USB slave/gadget base */
#define SM501_USB_GADGET                (0x060000)

/* USB slave/gadget data port base */
#define SM501_USB_GADGET_DATA           (0x070000)

/* Display controller/video engine base */
#define SM501_DC                        (0x080000)

/* common defines for the SM501 address registers */
#define SM501_ADDR_FLIP                 (1 << 31)
#define SM501_ADDR_EXT                  (1 << 27)
#define SM501_ADDR_CS1                  (1 << 26)
#define SM501_ADDR_MASK                 (0x3f << 26)

#define SM501_FIFO_MASK                 (0x3 << 16)
#define SM501_FIFO_1                    (0x0 << 16)
#define SM501_FIFO_3                    (0x1 << 16)
#define SM501_FIFO_7                    (0x2 << 16)
#define SM501_FIFO_11                   (0x3 << 16)

/* common registers for panel and the crt */
#define SM501_OFF_DC_H_TOT              (0x000)
#define SM501_OFF_DC_V_TOT              (0x008)
#define SM501_OFF_DC_H_SYNC             (0x004)
#define SM501_OFF_DC_V_SYNC             (0x00C)

#define SM501_DC_PANEL_CONTROL          (0x000)

#define SM501_DC_PANEL_CONTROL_FPEN     (1 << 27)
#define SM501_DC_PANEL_CONTROL_BIAS     (1 << 26)
#define SM501_DC_PANEL_CONTROL_DATA     (1 << 25)
#define SM501_DC_PANEL_CONTROL_VDD      (1 << 24)
#define SM501_DC_PANEL_CONTROL_DP       (1 << 23)

#define SM501_DC_PANEL_CONTROL_TFT_888  (0 << 21)
#define SM501_DC_PANEL_CONTROL_TFT_333  (1 << 21)
#define SM501_DC_PANEL_CONTROL_TFT_444  (2 << 21)

#define SM501_DC_PANEL_CONTROL_DE       (1 << 20)

#define SM501_DC_PANEL_CONTROL_LCD_TFT  (0 << 18)
#define SM501_DC_PANEL_CONTROL_LCD_STN8 (1 << 18)
#define SM501_DC_PANEL_CONTROL_LCD_STN12 (2 << 18)

#define SM501_DC_PANEL_CONTROL_CP       (1 << 14)
#define SM501_DC_PANEL_CONTROL_VSP      (1 << 13)
#define SM501_DC_PANEL_CONTROL_HSP      (1 << 12)
#define SM501_DC_PANEL_CONTROL_CK       (1 << 9)
#define SM501_DC_PANEL_CONTROL_TE       (1 << 8)
#define SM501_DC_PANEL_CONTROL_VPD      (1 << 7)
#define SM501_DC_PANEL_CONTROL_VP       (1 << 6)
#define SM501_DC_PANEL_CONTROL_HPD      (1 << 5)
#define SM501_DC_PANEL_CONTROL_HP       (1 << 4)
#define SM501_DC_PANEL_CONTROL_GAMMA    (1 << 3)
#define SM501_DC_PANEL_CONTROL_EN       (1 << 2)

#define SM501_DC_PANEL_CONTROL_8BPP     (0 << 0)
#define SM501_DC_PANEL_CONTROL_16BPP    (1 << 0)
#define SM501_DC_PANEL_CONTROL_32BPP    (2 << 0)


#define SM501_DC_PANEL_PANNING_CONTROL  (0x004)
#define SM501_DC_PANEL_COLOR_KEY        (0x008)
#define SM501_DC_PANEL_FB_ADDR          (0x00C)
#define SM501_DC_PANEL_FB_OFFSET        (0x010)
#define SM501_DC_PANEL_FB_WIDTH         (0x014)
#define SM501_DC_PANEL_FB_HEIGHT        (0x018)
#define SM501_DC_PANEL_TL_LOC           (0x01C)
#define SM501_DC_PANEL_BR_LOC           (0x020)
#define SM501_DC_PANEL_H_TOT            (0x024)
#define SM501_DC_PANEL_H_SYNC           (0x028)
#define SM501_DC_PANEL_V_TOT            (0x02C)
#define SM501_DC_PANEL_V_SYNC           (0x030)
#define SM501_DC_PANEL_CUR_LINE         (0x034)

#define SM501_DC_VIDEO_CONTROL          (0x040)
#define SM501_DC_VIDEO_FB0_ADDR         (0x044)
#define SM501_DC_VIDEO_FB_WIDTH         (0x048)
#define SM501_DC_VIDEO_FB0_LAST_ADDR    (0x04C)
#define SM501_DC_VIDEO_TL_LOC           (0x050)
#define SM501_DC_VIDEO_BR_LOC           (0x054)
#define SM501_DC_VIDEO_SCALE            (0x058)
#define SM501_DC_VIDEO_INIT_SCALE       (0x05C)
#define SM501_DC_VIDEO_YUV_CONSTANTS    (0x060)
#define SM501_DC_VIDEO_FB1_ADDR         (0x064)
#define SM501_DC_VIDEO_FB1_LAST_ADDR    (0x068)

#define SM501_DC_VIDEO_ALPHA_CONTROL    (0x080)
#define SM501_DC_VIDEO_ALPHA_FB_ADDR    (0x084)
#define SM501_DC_VIDEO_ALPHA_FB_OFFSET  (0x088)
#define SM501_DC_VIDEO_ALPHA_FB_LAST_ADDR (0x08C)
#define SM501_DC_VIDEO_ALPHA_TL_LOC     (0x090)
#define SM501_DC_VIDEO_ALPHA_BR_LOC     (0x094)
#define SM501_DC_VIDEO_ALPHA_SCALE      (0x098)
#define SM501_DC_VIDEO_ALPHA_INIT_SCALE (0x09C)
#define SM501_DC_VIDEO_ALPHA_CHROMA_KEY (0x0A0)
#define SM501_DC_VIDEO_ALPHA_COLOR_LOOKUP (0x0A4)

#define SM501_DC_PANEL_HWC_BASE         (0x0F0)
#define SM501_DC_PANEL_HWC_ADDR         (0x0F0)
#define SM501_DC_PANEL_HWC_LOC          (0x0F4)
#define SM501_DC_PANEL_HWC_COLOR_1_2    (0x0F8)
#define SM501_DC_PANEL_HWC_COLOR_3      (0x0FC)

#define SM501_HWC_EN                    (1 << 31)

#define SM501_OFF_HWC_ADDR              (0x00)
#define SM501_OFF_HWC_LOC               (0x04)
#define SM501_OFF_HWC_COLOR_1_2         (0x08)
#define SM501_OFF_HWC_COLOR_3           (0x0C)

#define SM501_DC_ALPHA_CONTROL          (0x100)
#define SM501_DC_ALPHA_FB_ADDR          (0x104)
#define SM501_DC_ALPHA_FB_OFFSET        (0x108)
#define SM501_DC_ALPHA_TL_LOC           (0x10C)
#define SM501_DC_ALPHA_BR_LOC           (0x110)
#define SM501_DC_ALPHA_CHROMA_KEY       (0x114)
#define SM501_DC_ALPHA_COLOR_LOOKUP     (0x118)

#define SM501_DC_CRT_CONTROL            (0x200)

#define SM501_DC_CRT_CONTROL_TVP        (1 << 15)
#define SM501_DC_CRT_CONTROL_CP         (1 << 14)
#define SM501_DC_CRT_CONTROL_VSP        (1 << 13)
#define SM501_DC_CRT_CONTROL_HSP        (1 << 12)
#define SM501_DC_CRT_CONTROL_VS         (1 << 11)
#define SM501_DC_CRT_CONTROL_BLANK      (1 << 10)
#define SM501_DC_CRT_CONTROL_SEL        (1 << 9)
#define SM501_DC_CRT_CONTROL_TE         (1 << 8)
#define SM501_DC_CRT_CONTROL_PIXEL_MASK (0xF << 4)
#define SM501_DC_CRT_CONTROL_GAMMA      (1 << 3)
#define SM501_DC_CRT_CONTROL_ENABLE     (1 << 2)

#define SM501_DC_CRT_CONTROL_8BPP       (0 << 0)
#define SM501_DC_CRT_CONTROL_16BPP      (1 << 0)
#define SM501_DC_CRT_CONTROL_32BPP      (2 << 0)

#define SM501_DC_CRT_FB_ADDR            (0x204)
#define SM501_DC_CRT_FB_OFFSET          (0x208)
#define SM501_DC_CRT_H_TOT              (0x20C)
#define SM501_DC_CRT_H_SYNC             (0x210)
#define SM501_DC_CRT_V_TOT              (0x214)
#define SM501_DC_CRT_V_SYNC             (0x218)
#define SM501_DC_CRT_SIGNATURE_ANALYZER (0x21C)
#define SM501_DC_CRT_CUR_LINE           (0x220)
#define SM501_DC_CRT_MONITOR_DETECT     (0x224)

#define SM501_DC_CRT_HWC_BASE           (0x230)
#define SM501_DC_CRT_HWC_ADDR           (0x230)
#define SM501_DC_CRT_HWC_LOC            (0x234)
#define SM501_DC_CRT_HWC_COLOR_1_2      (0x238)
#define SM501_DC_CRT_HWC_COLOR_3        (0x23C)

#define SM501_DC_PANEL_PALETTE          (0x400)

#define SM501_DC_VIDEO_PALETTE          (0x800)

#define SM501_DC_CRT_PALETTE            (0xC00)

/* Zoom Video port base */
#define SM501_ZVPORT                    (0x090000)

/* AC97/I2S base */
#define SM501_AC97                      (0x0A0000)

/* 8051 micro controller base */
#define SM501_UCONTROLLER               (0x0B0000)

/* 8051 micro controller SRAM base */
#define SM501_UCONTROLLER_SRAM          (0x0C0000)

/* DMA base */
#define SM501_DMA                       (0x0D0000)

/* 2d engine base */
#define SM501_2D_ENGINE                 (0x100000)
#define SM501_2D_SOURCE                 (0x00)
#define SM501_2D_DESTINATION            (0x04)
#define SM501_2D_DIMENSION              (0x08)
#define SM501_2D_CONTROL                (0x0C)
#define SM501_2D_PITCH                  (0x10)
#define SM501_2D_FOREGROUND             (0x14)
#define SM501_2D_BACKGROUND             (0x18)
#define SM501_2D_STRETCH                (0x1C)
#define SM501_2D_COLOR_COMPARE          (0x20)
#define SM501_2D_COLOR_COMPARE_MASK     (0x24)
#define SM501_2D_MASK                   (0x28)
#define SM501_2D_CLIP_TL                (0x2C)
#define SM501_2D_CLIP_BR                (0x30)
#define SM501_2D_MONO_PATTERN_LOW       (0x34)
#define SM501_2D_MONO_PATTERN_HIGH      (0x38)
#define SM501_2D_WINDOW_WIDTH           (0x3C)
#define SM501_2D_SOURCE_BASE            (0x40)
#define SM501_2D_DESTINATION_BASE       (0x44)
#define SM501_2D_ALPHA                  (0x48)
#define SM501_2D_WRAP                   (0x4C)
#define SM501_2D_STATUS                 (0x50)

#define SM501_CSC_Y_SOURCE_BASE         (0xC8)
#define SM501_CSC_CONSTANTS             (0xCC)
#define SM501_CSC_Y_SOURCE_X            (0xD0)
#define SM501_CSC_Y_SOURCE_Y            (0xD4)
#define SM501_CSC_U_SOURCE_BASE         (0xD8)
#define SM501_CSC_V_SOURCE_BASE         (0xDC)
#define SM501_CSC_SOURCE_DIMENSION      (0xE0)
#define SM501_CSC_SOURCE_PITCH          (0xE4)
#define SM501_CSC_DESTINATION           (0xE8)
#define SM501_CSC_DESTINATION_DIMENSION (0xEC)
#define SM501_CSC_DESTINATION_PITCH     (0xF0)
#define SM501_CSC_SCALE_FACTOR          (0xF4)
#define SM501_CSC_DESTINATION_BASE      (0xF8)
#define SM501_CSC_CONTROL               (0xFC)

/* 2d engine data port base */
#define SM501_2D_ENGINE_DATA            (0x110000)

/* end of register definitions */

#define SM501_HWC_WIDTH                       (64)
#define SM501_HWC_HEIGHT                      (64)

/* SM501 local memory size taken from "linux/drivers/mfd/sm501.c" */
static const uint32_t sm501_mem_local_size[] = {
    [0] = 4 * MiB,
    [1] = 8 * MiB,
    [2] = 16 * MiB,
    [3] = 32 * MiB,
    [4] = 64 * MiB,
    [5] = 2 * MiB,
};
#define get_local_mem_size(s) sm501_mem_local_size[(s)->local_mem_size_index]

typedef struct SM501State {
    /* graphic console status */
    QemuConsole *con;

    /* status & internal resources */
    uint32_t local_mem_size_index;
    uint8_t *local_mem;
    MemoryRegion local_mem_region;
    MemoryRegion mmio_region;
    MemoryRegion system_config_region;
    MemoryRegion i2c_region;
    MemoryRegion disp_ctrl_region;
    MemoryRegion twoD_engine_region;
    uint32_t last_width;
    uint32_t last_height;
    bool do_full_update; /* perform a full update next time */
    I2CBus *i2c_bus;

    /* mmio registers */
    uint32_t system_control;
    uint32_t misc_control;
    uint32_t gpio_31_0_control;
    uint32_t gpio_63_32_control;
    uint32_t dram_control;
    uint32_t arbitration_control;
    uint32_t irq_mask;
    uint32_t misc_timing;
    uint32_t power_mode_control;

    uint8_t i2c_byte_count;
    uint8_t i2c_status;
    uint8_t i2c_addr;
    uint8_t i2c_data[16];

    uint32_t uart0_ier;
    uint32_t uart0_lcr;
    uint32_t uart0_mcr;
    uint32_t uart0_scr;

    uint8_t dc_palette[DC_PALETTE_ENTRIES];

    uint32_t dc_panel_control;
    uint32_t dc_panel_panning_control;
    uint32_t dc_panel_fb_addr;
    uint32_t dc_panel_fb_offset;
    uint32_t dc_panel_fb_width;
    uint32_t dc_panel_fb_height;
    uint32_t dc_panel_tl_location;
    uint32_t dc_panel_br_location;
    uint32_t dc_panel_h_total;
    uint32_t dc_panel_h_sync;
    uint32_t dc_panel_v_total;
    uint32_t dc_panel_v_sync;

    uint32_t dc_panel_hwc_addr;
    uint32_t dc_panel_hwc_location;
    uint32_t dc_panel_hwc_color_1_2;
    uint32_t dc_panel_hwc_color_3;

    uint32_t dc_video_control;

    uint32_t dc_crt_control;
    uint32_t dc_crt_fb_addr;
    uint32_t dc_crt_fb_offset;
    uint32_t dc_crt_h_total;
    uint32_t dc_crt_h_sync;
    uint32_t dc_crt_v_total;
    uint32_t dc_crt_v_sync;

    uint32_t dc_crt_hwc_addr;
    uint32_t dc_crt_hwc_location;
    uint32_t dc_crt_hwc_color_1_2;
    uint32_t dc_crt_hwc_color_3;

    uint32_t twoD_source;
    uint32_t twoD_destination;
    uint32_t twoD_dimension;
    uint32_t twoD_control;
    uint32_t twoD_pitch;
    uint32_t twoD_foreground;
    uint32_t twoD_background;
    uint32_t twoD_stretch;
    uint32_t twoD_color_compare;
    uint32_t twoD_color_compare_mask;
    uint32_t twoD_mask;
    uint32_t twoD_clip_tl;
    uint32_t twoD_clip_br;
    uint32_t twoD_mono_pattern_low;
    uint32_t twoD_mono_pattern_high;
    uint32_t twoD_window_width;
    uint32_t twoD_source_base;
    uint32_t twoD_destination_base;
    uint32_t twoD_alpha;
    uint32_t twoD_wrap;
} SM501State;

static uint32_t get_local_mem_size_index(uint32_t size)
{
    uint32_t norm_size = 0;
    int i, index = 0;

    for (i = 0; i < ARRAY_SIZE(sm501_mem_local_size); i++) {
        uint32_t new_size = sm501_mem_local_size[i];
        if (new_size >= size) {
            if (norm_size == 0 || norm_size > new_size) {
                norm_size = new_size;
                index = i;
            }
        }
    }

    return index;
}

static ram_addr_t get_fb_addr(SM501State *s, int crt)
{
    return (crt ? s->dc_crt_fb_addr : s->dc_panel_fb_addr) & 0x3FFFFF0;
}

static inline int get_width(SM501State *s, int crt)
{
    int width = crt ? s->dc_crt_h_total : s->dc_panel_h_total;
    return (width & 0x00000FFF) + 1;
}

static inline int get_height(SM501State *s, int crt)
{
    int height = crt ? s->dc_crt_v_total : s->dc_panel_v_total;
    return (height & 0x00000FFF) + 1;
}

static inline int get_bpp(SM501State *s, int crt)
{
    int bpp = crt ? s->dc_crt_control : s->dc_panel_control;
    return 1 << (bpp & 3);
}

/**
 * Check the availability of hardware cursor.
 * @param crt  0 for PANEL, 1 for CRT.
 */
static inline int is_hwc_enabled(SM501State *state, int crt)
{
    uint32_t addr = crt ? state->dc_crt_hwc_addr : state->dc_panel_hwc_addr;
    return addr & SM501_HWC_EN;
}

/**
 * Get the address which holds cursor pattern data.
 * @param crt  0 for PANEL, 1 for CRT.
 */
static inline uint8_t *get_hwc_address(SM501State *state, int crt)
{
    uint32_t addr = crt ? state->dc_crt_hwc_addr : state->dc_panel_hwc_addr;
    return state->local_mem + (addr & 0x03FFFFF0);
}

/**
 * Get the cursor position in y coordinate.
 * @param crt  0 for PANEL, 1 for CRT.
 */
static inline uint32_t get_hwc_y(SM501State *state, int crt)
{
    uint32_t location = crt ? state->dc_crt_hwc_location
                            : state->dc_panel_hwc_location;
    return (location & 0x07FF0000) >> 16;
}

/**
 * Get the cursor position in x coordinate.
 * @param crt  0 for PANEL, 1 for CRT.
 */
static inline uint32_t get_hwc_x(SM501State *state, int crt)
{
    uint32_t location = crt ? state->dc_crt_hwc_location
                            : state->dc_panel_hwc_location;
    return location & 0x000007FF;
}

/**
 * Get the hardware cursor palette.
 * @param crt  0 for PANEL, 1 for CRT.
 * @param palette  pointer to a [3 * 3] array to store color values in
 */
static inline void get_hwc_palette(SM501State *state, int crt, uint8_t *palette)
{
    int i;
    uint32_t color_reg;
    uint16_t rgb565;

    for (i = 0; i < 3; i++) {
        if (i + 1 == 3) {
            color_reg = crt ? state->dc_crt_hwc_color_3
                            : state->dc_panel_hwc_color_3;
        } else {
            color_reg = crt ? state->dc_crt_hwc_color_1_2
                            : state->dc_panel_hwc_color_1_2;
        }

        if (i + 1 == 2) {
            rgb565 = (color_reg >> 16) & 0xFFFF;
        } else {
            rgb565 = color_reg & 0xFFFF;
        }
        palette[i * 3 + 0] = ((rgb565 >> 11) * 527 + 23) >> 6; /* r */
        palette[i * 3 + 1] = (((rgb565 >> 5) & 0x3f) * 259 + 33) >> 6; /* g */
        palette[i * 3 + 2] = ((rgb565 & 0x1f) * 527 + 23) >> 6; /* b */
    }
}

static inline void hwc_invalidate(SM501State *s, int crt)
{
    int w = get_width(s, crt);
    int h = get_height(s, crt);
    int bpp = get_bpp(s, crt);
    int start = get_hwc_y(s, crt);
    int end = MIN(h, start + SM501_HWC_HEIGHT) + 1;

    start *= w * bpp;
    end *= w * bpp;

    memory_region_set_dirty(&s->local_mem_region,
                            get_fb_addr(s, crt) + start, end - start);
}

static void sm501_2d_operation(SM501State *s)
{
    /* obtain operation parameters */
    int operation = (s->twoD_control >> 16) & 0x1f;
    int rtl = s->twoD_control & 0x8000000;
    int src_x = (s->twoD_source >> 16) & 0x01FFF;
    int src_y = s->twoD_source & 0xFFFF;
    int dst_x = (s->twoD_destination >> 16) & 0x01FFF;
    int dst_y = s->twoD_destination & 0xFFFF;
    int operation_width = (s->twoD_dimension >> 16) & 0x1FFF;
    int operation_height = s->twoD_dimension & 0xFFFF;
    uint32_t color = s->twoD_foreground;
    int format_flags = (s->twoD_stretch >> 20) & 0x3;
    int addressing = (s->twoD_stretch >> 16) & 0xF;
    int rop_mode = (s->twoD_control >> 15) & 0x1; /* 1 for rop2, else rop3 */
    /* 1 if rop2 source is the pattern, otherwise the source is the bitmap */
    int rop2_source_is_pattern = (s->twoD_control >> 14) & 0x1;
    int rop = s->twoD_control & 0xFF;
    uint32_t src_base = s->twoD_source_base & 0x03FFFFFF;
    uint32_t dst_base = s->twoD_destination_base & 0x03FFFFFF;

    /* get frame buffer info */
    uint8_t *src = s->local_mem + src_base;
    uint8_t *dst = s->local_mem + dst_base;
    int src_width = s->twoD_pitch & 0x1FFF;
    int dst_width = (s->twoD_pitch >> 16) & 0x1FFF;
    int crt = (s->dc_crt_control & SM501_DC_CRT_CONTROL_SEL) ? 1 : 0;
    int fb_len = get_width(s, crt) * get_height(s, crt) * get_bpp(s, crt);

    if (addressing != 0x0) {
        printf("%s: only XY addressing is supported.\n", __func__);
        abort();
    }

    if (rop_mode == 0) {
        if (rop != 0xcc) {
            /* Anything other than plain copies are not supported */
            qemu_log_mask(LOG_UNIMP, "sm501: rop3 mode with rop %x is not "
                          "supported.\n", rop);
        }
    } else {
        if (rop2_source_is_pattern && rop != 0x5) {
            /* For pattern source, we support only inverse dest */
            qemu_log_mask(LOG_UNIMP, "sm501: rop2 source being the pattern and "
                          "rop %x is not supported.\n", rop);
        } else {
            if (rop != 0x5 && rop != 0xc) {
                /* Anything other than plain copies or inverse dest is not
                 * supported */
                qemu_log_mask(LOG_UNIMP, "sm501: rop mode %x is not "
                              "supported.\n", rop);
            }
        }
    }

    if ((s->twoD_source_base & 0x08000000) ||
        (s->twoD_destination_base & 0x08000000)) {
        printf("%s: only local memory is supported.\n", __func__);
        abort();
    }

    switch (operation) {
    case 0x00: /* copy area */
#define COPY_AREA(_bpp, _pixel_type, rtl) {                                   \
        int y, x, index_d, index_s;                                           \
        for (y = 0; y < operation_height; y++) {                              \
            for (x = 0; x < operation_width; x++) {                           \
                _pixel_type val;                                              \
                                                                              \
                if (rtl) {                                                    \
                    index_s = ((src_y - y) * src_width + src_x - x) * _bpp;   \
                    index_d = ((dst_y - y) * dst_width + dst_x - x) * _bpp;   \
                } else {                                                      \
                    index_s = ((src_y + y) * src_width + src_x + x) * _bpp;   \
                    index_d = ((dst_y + y) * dst_width + dst_x + x) * _bpp;   \
                }                                                             \
                if (rop_mode == 1 && rop == 5) {                              \
                    /* Invert dest */                                         \
                    val = ~*(_pixel_type *)&dst[index_d];                     \
                } else {                                                      \
                    val = *(_pixel_type *)&src[index_s];                      \
                }                                                             \
                *(_pixel_type *)&dst[index_d] = val;                          \
            }                                                                 \
        }                                                                     \
    }
        switch (format_flags) {
        case 0:
            COPY_AREA(1, uint8_t, rtl);
            break;
        case 1:
            COPY_AREA(2, uint16_t, rtl);
            break;
        case 2:
            COPY_AREA(4, uint32_t, rtl);
            break;
        }
        break;

    case 0x01: /* fill rectangle */
#define FILL_RECT(_bpp, _pixel_type) {                                      \
        int y, x;                                                           \
        for (y = 0; y < operation_height; y++) {                            \
            for (x = 0; x < operation_width; x++) {                         \
                int index = ((dst_y + y) * dst_width + dst_x + x) * _bpp;   \
                *(_pixel_type *)&dst[index] = (_pixel_type)color;           \
            }                                                               \
        }                                                                   \
    }

        switch (format_flags) {
        case 0:
            FILL_RECT(1, uint8_t);
            break;
        case 1:
            color = cpu_to_le16(color);
            FILL_RECT(2, uint16_t);
            break;
        case 2:
            color = cpu_to_le32(color);
            FILL_RECT(4, uint32_t);
            break;
        }
        break;

    default:
        printf("non-implemented SM501 2D operation. %d\n", operation);
        abort();
        break;
    }

    if (dst_base >= get_fb_addr(s, crt) &&
        dst_base <= get_fb_addr(s, crt) + fb_len) {
        int dst_len = MIN(fb_len, ((dst_y + operation_height - 1) * dst_width +
                           dst_x + operation_width) * (1 << format_flags));
        if (dst_len) {
            memory_region_set_dirty(&s->local_mem_region, dst_base, dst_len);
        }
    }
}

static uint64_t sm501_system_config_read(void *opaque, hwaddr addr,
                                         unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    uint32_t ret = 0;
    SM501_DPRINTF("sm501 system config regs : read addr=%x\n", (int)addr);

    switch (addr) {
    case SM501_SYSTEM_CONTROL:
        ret = s->system_control;
        break;
    case SM501_MISC_CONTROL:
        ret = s->misc_control;
        break;
    case SM501_GPIO31_0_CONTROL:
        ret = s->gpio_31_0_control;
        break;
    case SM501_GPIO63_32_CONTROL:
        ret = s->gpio_63_32_control;
        break;
    case SM501_DEVICEID:
        ret = 0x050100A0;
        break;
    case SM501_DRAM_CONTROL:
        ret = (s->dram_control & 0x07F107C0) | s->local_mem_size_index << 13;
        break;
    case SM501_ARBTRTN_CONTROL:
        ret = s->arbitration_control;
        break;
    case SM501_COMMAND_LIST_STATUS:
        ret = 0x00180002; /* FIFOs are empty, everything idle */
        break;
    case SM501_IRQ_MASK:
        ret = s->irq_mask;
        break;
    case SM501_MISC_TIMING:
        /* TODO : simulate gate control */
        ret = s->misc_timing;
        break;
    case SM501_CURRENT_GATE:
        /* TODO : simulate gate control */
        ret = 0x00021807;
        break;
    case SM501_CURRENT_CLOCK:
        ret = 0x2A1A0A09;
        break;
    case SM501_POWER_MODE_CONTROL:
        ret = s->power_mode_control;
        break;
    case SM501_ENDIAN_CONTROL:
        ret = 0; /* Only default little endian mode is supported */
        break;

    default:
        printf("sm501 system config : not implemented register read."
               " addr=%x\n", (int)addr);
        abort();
    }

    return ret;
}

static void sm501_system_config_write(void *opaque, hwaddr addr,
                                      uint64_t value, unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 system config regs : write addr=%x, val=%x\n",
                  (uint32_t)addr, (uint32_t)value);

    switch (addr) {
    case SM501_SYSTEM_CONTROL:
        s->system_control &= 0x10DB0000;
        s->system_control |= value & 0xEF00B8F7;
        break;
    case SM501_MISC_CONTROL:
        s->misc_control &= 0xEF;
        s->misc_control |= value & 0xFF7FFF10;
        break;
    case SM501_GPIO31_0_CONTROL:
        s->gpio_31_0_control = value;
        break;
    case SM501_GPIO63_32_CONTROL:
        s->gpio_63_32_control = value & 0xFF80FFFF;
        break;
    case SM501_DRAM_CONTROL:
        s->local_mem_size_index = (value >> 13) & 0x7;
        /* TODO : check validity of size change */
        s->dram_control &= 0x80000000;
        s->dram_control |= value & 0x7FFFFFC3;
        break;
    case SM501_ARBTRTN_CONTROL:
        s->arbitration_control = value & 0x37777777;
        break;
    case SM501_IRQ_MASK:
        s->irq_mask = value & 0xFFDF3F5F;
        break;
    case SM501_MISC_TIMING:
        s->misc_timing = value & 0xF31F1FFF;
        break;
    case SM501_POWER_MODE_0_GATE:
    case SM501_POWER_MODE_1_GATE:
    case SM501_POWER_MODE_0_CLOCK:
    case SM501_POWER_MODE_1_CLOCK:
        /* TODO : simulate gate & clock control */
        break;
    case SM501_POWER_MODE_CONTROL:
        s->power_mode_control = value & 0x00000003;
        break;
    case SM501_ENDIAN_CONTROL:
        if (value & 0x00000001) {
            printf("sm501 system config : big endian mode not implemented.\n");
            abort();
        }
        break;

    default:
        printf("sm501 system config : not implemented register write."
               " addr=%x, val=%x\n", (int)addr, (uint32_t)value);
        abort();
    }
}

static const MemoryRegionOps sm501_system_config_ops = {
    .read = sm501_system_config_read,
    .write = sm501_system_config_write,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t sm501_i2c_read(void *opaque, hwaddr addr, unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    uint8_t ret = 0;

    switch (addr) {
    case SM501_I2C_BYTE_COUNT:
        ret = s->i2c_byte_count;
        break;
    case SM501_I2C_STATUS:
        ret = s->i2c_status;
        break;
    case SM501_I2C_SLAVE_ADDRESS:
        ret = s->i2c_addr;
        break;
    case SM501_I2C_DATA ... SM501_I2C_DATA + 15:
        ret = s->i2c_data[addr - SM501_I2C_DATA];
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "sm501 i2c : not implemented register read."
                      " addr=0x%" HWADDR_PRIx "\n", addr);
    }

    SM501_DPRINTF("sm501 i2c regs : read addr=%" HWADDR_PRIx " val=%x\n",
                  addr, ret);
    return ret;
}

static void sm501_i2c_write(void *opaque, hwaddr addr, uint64_t value,
                            unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 i2c regs : write addr=%" HWADDR_PRIx
                  " val=%" PRIx64 "\n", addr, value);

    switch (addr) {
    case SM501_I2C_BYTE_COUNT:
        s->i2c_byte_count = value & 0xf;
        break;
    case SM501_I2C_CONTROL:
        if (value & SM501_I2C_CONTROL_ENABLE) {
            if (value & SM501_I2C_CONTROL_START) {
                int res = i2c_start_transfer(s->i2c_bus,
                                             s->i2c_addr >> 1,
                                             s->i2c_addr & 1);
                s->i2c_status |= (res ? SM501_I2C_STATUS_ERROR : 0);
                if (!res) {
                    int i;
                    SM501_DPRINTF("sm501 i2c : transferring %d bytes to 0x%x\n",
                                  s->i2c_byte_count + 1, s->i2c_addr >> 1);
                    for (i = 0; i <= s->i2c_byte_count; i++) {
                        res = i2c_send_recv(s->i2c_bus, &s->i2c_data[i],
                                            !(s->i2c_addr & 1));
                        if (res) {
                            SM501_DPRINTF("sm501 i2c : transfer failed"
                                          " i=%d, res=%d\n", i, res);
                            s->i2c_status |= SM501_I2C_STATUS_ERROR;
                            return;
                        }
                    }
                    if (i) {
                        SM501_DPRINTF("sm501 i2c : transferred %d bytes\n", i);
                        s->i2c_status = SM501_I2C_STATUS_COMPLETE;
                    }
                }
            } else {
                SM501_DPRINTF("sm501 i2c : end transfer\n");
                i2c_end_transfer(s->i2c_bus);
                s->i2c_status &= ~SM501_I2C_STATUS_ERROR;
            }
        }
        break;
    case SM501_I2C_RESET:
        if ((value & SM501_I2C_RESET_ERROR) == 0) {
            s->i2c_status &= ~SM501_I2C_STATUS_ERROR;
        }
        break;
    case SM501_I2C_SLAVE_ADDRESS:
        s->i2c_addr = value & 0xff;
        break;
    case SM501_I2C_DATA ... SM501_I2C_DATA + 15:
        s->i2c_data[addr - SM501_I2C_DATA] = value & 0xff;
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "sm501 i2c : not implemented register write. "
                      "addr=0x%" HWADDR_PRIx " val=%" PRIx64 "\n", addr, value);
    }
}

static const MemoryRegionOps sm501_i2c_ops = {
    .read = sm501_i2c_read,
    .write = sm501_i2c_write,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint32_t sm501_palette_read(void *opaque, hwaddr addr)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 palette read addr=%x\n", (int)addr);

    /* TODO : consider BYTE/WORD access */
    /* TODO : consider endian */

    assert(range_covers_byte(0, 0x400 * 3, addr));
    return *(uint32_t *)&s->dc_palette[addr];
}

static void sm501_palette_write(void *opaque, hwaddr addr,
                                uint32_t value)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 palette write addr=%x, val=%x\n",
                  (int)addr, value);

    /* TODO : consider BYTE/WORD access */
    /* TODO : consider endian */

    assert(range_covers_byte(0, 0x400 * 3, addr));
    *(uint32_t *)&s->dc_palette[addr] = value;
    s->do_full_update = true;
}

static uint64_t sm501_disp_ctrl_read(void *opaque, hwaddr addr,
                                     unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    uint32_t ret = 0;
    SM501_DPRINTF("sm501 disp ctrl regs : read addr=%x\n", (int)addr);

    switch (addr) {

    case SM501_DC_PANEL_CONTROL:
        ret = s->dc_panel_control;
        break;
    case SM501_DC_PANEL_PANNING_CONTROL:
        ret = s->dc_panel_panning_control;
        break;
    case SM501_DC_PANEL_COLOR_KEY:
        /* Not implemented yet */
        break;
    case SM501_DC_PANEL_FB_ADDR:
        ret = s->dc_panel_fb_addr;
        break;
    case SM501_DC_PANEL_FB_OFFSET:
        ret = s->dc_panel_fb_offset;
        break;
    case SM501_DC_PANEL_FB_WIDTH:
        ret = s->dc_panel_fb_width;
        break;
    case SM501_DC_PANEL_FB_HEIGHT:
        ret = s->dc_panel_fb_height;
        break;
    case SM501_DC_PANEL_TL_LOC:
        ret = s->dc_panel_tl_location;
        break;
    case SM501_DC_PANEL_BR_LOC:
        ret = s->dc_panel_br_location;
        break;

    case SM501_DC_PANEL_H_TOT:
        ret = s->dc_panel_h_total;
        break;
    case SM501_DC_PANEL_H_SYNC:
        ret = s->dc_panel_h_sync;
        break;
    case SM501_DC_PANEL_V_TOT:
        ret = s->dc_panel_v_total;
        break;
    case SM501_DC_PANEL_V_SYNC:
        ret = s->dc_panel_v_sync;
        break;

    case SM501_DC_PANEL_HWC_ADDR:
        ret = s->dc_panel_hwc_addr;
        break;
    case SM501_DC_PANEL_HWC_LOC:
        ret = s->dc_panel_hwc_location;
        break;
    case SM501_DC_PANEL_HWC_COLOR_1_2:
        ret = s->dc_panel_hwc_color_1_2;
        break;
    case SM501_DC_PANEL_HWC_COLOR_3:
        ret = s->dc_panel_hwc_color_3;
        break;

    case SM501_DC_VIDEO_CONTROL:
        ret = s->dc_video_control;
        break;

    case SM501_DC_CRT_CONTROL:
        ret = s->dc_crt_control;
        break;
    case SM501_DC_CRT_FB_ADDR:
        ret = s->dc_crt_fb_addr;
        break;
    case SM501_DC_CRT_FB_OFFSET:
        ret = s->dc_crt_fb_offset;
        break;
    case SM501_DC_CRT_H_TOT:
        ret = s->dc_crt_h_total;
        break;
    case SM501_DC_CRT_H_SYNC:
        ret = s->dc_crt_h_sync;
        break;
    case SM501_DC_CRT_V_TOT:
        ret = s->dc_crt_v_total;
        break;
    case SM501_DC_CRT_V_SYNC:
        ret = s->dc_crt_v_sync;
        break;

    case SM501_DC_CRT_HWC_ADDR:
        ret = s->dc_crt_hwc_addr;
        break;
    case SM501_DC_CRT_HWC_LOC:
        ret = s->dc_crt_hwc_location;
        break;
    case SM501_DC_CRT_HWC_COLOR_1_2:
        ret = s->dc_crt_hwc_color_1_2;
        break;
    case SM501_DC_CRT_HWC_COLOR_3:
        ret = s->dc_crt_hwc_color_3;
        break;

    case SM501_DC_PANEL_PALETTE ... SM501_DC_PANEL_PALETTE + 0x400 * 3 - 4:
        ret = sm501_palette_read(opaque, addr - SM501_DC_PANEL_PALETTE);
        break;

    default:
        printf("sm501 disp ctrl : not implemented register read."
               " addr=%x\n", (int)addr);
        abort();
    }

    return ret;
}

static void sm501_disp_ctrl_write(void *opaque, hwaddr addr,
                                  uint64_t value, unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 disp ctrl regs : write addr=%x, val=%x\n",
                  (unsigned)addr, (unsigned)value);

    switch (addr) {
    case SM501_DC_PANEL_CONTROL:
        s->dc_panel_control = value & 0x0FFF73FF;
        break;
    case SM501_DC_PANEL_PANNING_CONTROL:
        s->dc_panel_panning_control = value & 0xFF3FFF3F;
        break;
    case SM501_DC_PANEL_COLOR_KEY:
        /* Not implemented yet */
        break;
    case SM501_DC_PANEL_FB_ADDR:
        s->dc_panel_fb_addr = value & 0x8FFFFFF0;
        if (value & 0x8000000) {
            qemu_log_mask(LOG_UNIMP, "Panel external memory not supported\n");
        }
        s->do_full_update = true;
        break;
    case SM501_DC_PANEL_FB_OFFSET:
        s->dc_panel_fb_offset = value & 0x3FF03FF0;
        break;
    case SM501_DC_PANEL_FB_WIDTH:
        s->dc_panel_fb_width = value & 0x0FFF0FFF;
        break;
    case SM501_DC_PANEL_FB_HEIGHT:
        s->dc_panel_fb_height = value & 0x0FFF0FFF;
        break;
    case SM501_DC_PANEL_TL_LOC:
        s->dc_panel_tl_location = value & 0x07FF07FF;
        break;
    case SM501_DC_PANEL_BR_LOC:
        s->dc_panel_br_location = value & 0x07FF07FF;
        break;

    case SM501_DC_PANEL_H_TOT:
        s->dc_panel_h_total = value & 0x0FFF0FFF;
        break;
    case SM501_DC_PANEL_H_SYNC:
        s->dc_panel_h_sync = value & 0x00FF0FFF;
        break;
    case SM501_DC_PANEL_V_TOT:
        s->dc_panel_v_total = value & 0x0FFF0FFF;
        break;
    case SM501_DC_PANEL_V_SYNC:
        s->dc_panel_v_sync = value & 0x003F0FFF;
        break;

    case SM501_DC_PANEL_HWC_ADDR:
        value &= 0x8FFFFFF0;
        if (value != s->dc_panel_hwc_addr) {
            hwc_invalidate(s, 0);
            s->dc_panel_hwc_addr = value;
        }
        break;
    case SM501_DC_PANEL_HWC_LOC:
        value &= 0x0FFF0FFF;
        if (value != s->dc_panel_hwc_location) {
            hwc_invalidate(s, 0);
            s->dc_panel_hwc_location = value;
        }
        break;
    case SM501_DC_PANEL_HWC_COLOR_1_2:
        s->dc_panel_hwc_color_1_2 = value;
        break;
    case SM501_DC_PANEL_HWC_COLOR_3:
        s->dc_panel_hwc_color_3 = value & 0x0000FFFF;
        break;

    case SM501_DC_VIDEO_CONTROL:
        s->dc_video_control = value & 0x00037FFF;
        break;

    case SM501_DC_CRT_CONTROL:
        s->dc_crt_control = value & 0x0003FFFF;
        break;
    case SM501_DC_CRT_FB_ADDR:
        s->dc_crt_fb_addr = value & 0x8FFFFFF0;
        if (value & 0x8000000) {
            qemu_log_mask(LOG_UNIMP, "CRT external memory not supported\n");
        }
        s->do_full_update = true;
        break;
    case SM501_DC_CRT_FB_OFFSET:
        s->dc_crt_fb_offset = value & 0x3FF03FF0;
        break;
    case SM501_DC_CRT_H_TOT:
        s->dc_crt_h_total = value & 0x0FFF0FFF;
        break;
    case SM501_DC_CRT_H_SYNC:
        s->dc_crt_h_sync = value & 0x00FF0FFF;
        break;
    case SM501_DC_CRT_V_TOT:
        s->dc_crt_v_total = value & 0x0FFF0FFF;
        break;
    case SM501_DC_CRT_V_SYNC:
        s->dc_crt_v_sync = value & 0x003F0FFF;
        break;

    case SM501_DC_CRT_HWC_ADDR:
        value &= 0x8FFFFFF0;
        if (value != s->dc_crt_hwc_addr) {
            hwc_invalidate(s, 1);
            s->dc_crt_hwc_addr = value;
        }
        break;
    case SM501_DC_CRT_HWC_LOC:
        value &= 0x0FFF0FFF;
        if (value != s->dc_crt_hwc_location) {
            hwc_invalidate(s, 1);
            s->dc_crt_hwc_location = value;
        }
        break;
    case SM501_DC_CRT_HWC_COLOR_1_2:
        s->dc_crt_hwc_color_1_2 = value;
        break;
    case SM501_DC_CRT_HWC_COLOR_3:
        s->dc_crt_hwc_color_3 = value & 0x0000FFFF;
        break;

    case SM501_DC_PANEL_PALETTE ... SM501_DC_PANEL_PALETTE + 0x400 * 3 - 4:
        sm501_palette_write(opaque, addr - SM501_DC_PANEL_PALETTE, value);
        break;

    default:
        printf("sm501 disp ctrl : not implemented register write."
               " addr=%x, val=%x\n", (int)addr, (unsigned)value);
        abort();
    }
}

static const MemoryRegionOps sm501_disp_ctrl_ops = {
    .read = sm501_disp_ctrl_read,
    .write = sm501_disp_ctrl_write,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static uint64_t sm501_2d_engine_read(void *opaque, hwaddr addr,
                                     unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    uint32_t ret = 0;
    SM501_DPRINTF("sm501 2d engine regs : read addr=%x\n", (int)addr);

    switch (addr) {
    case SM501_2D_SOURCE:
        ret = s->twoD_source;
        break;
    case SM501_2D_DESTINATION:
        ret = s->twoD_destination;
        break;
    case SM501_2D_DIMENSION:
        ret = s->twoD_dimension;
        break;
    case SM501_2D_CONTROL:
        ret = s->twoD_control;
        break;
    case SM501_2D_PITCH:
        ret = s->twoD_pitch;
        break;
    case SM501_2D_FOREGROUND:
        ret = s->twoD_foreground;
        break;
    case SM501_2D_BACKGROUND:
        ret = s->twoD_background;
        break;
    case SM501_2D_STRETCH:
        ret = s->twoD_stretch;
        break;
    case SM501_2D_COLOR_COMPARE:
        ret = s->twoD_color_compare;
        break;
    case SM501_2D_COLOR_COMPARE_MASK:
        ret = s->twoD_color_compare_mask;
        break;
    case SM501_2D_MASK:
        ret = s->twoD_mask;
        break;
    case SM501_2D_CLIP_TL:
        ret = s->twoD_clip_tl;
        break;
    case SM501_2D_CLIP_BR:
        ret = s->twoD_clip_br;
        break;
    case SM501_2D_MONO_PATTERN_LOW:
        ret = s->twoD_mono_pattern_low;
        break;
    case SM501_2D_MONO_PATTERN_HIGH:
        ret = s->twoD_mono_pattern_high;
        break;
    case SM501_2D_WINDOW_WIDTH:
        ret = s->twoD_window_width;
        break;
    case SM501_2D_SOURCE_BASE:
        ret = s->twoD_source_base;
        break;
    case SM501_2D_DESTINATION_BASE:
        ret = s->twoD_destination_base;
        break;
    case SM501_2D_ALPHA:
        ret = s->twoD_alpha;
        break;
    case SM501_2D_WRAP:
        ret = s->twoD_wrap;
        break;
    case SM501_2D_STATUS:
        ret = 0; /* Should return interrupt status */
        break;
    default:
        printf("sm501 disp ctrl : not implemented register read."
               " addr=%x\n", (int)addr);
        abort();
    }

    return ret;
}

static void sm501_2d_engine_write(void *opaque, hwaddr addr,
                                  uint64_t value, unsigned size)
{
    SM501State *s = (SM501State *)opaque;
    SM501_DPRINTF("sm501 2d engine regs : write addr=%x, val=%x\n",
                  (unsigned)addr, (unsigned)value);

    switch (addr) {
    case SM501_2D_SOURCE:
        s->twoD_source = value;
        break;
    case SM501_2D_DESTINATION:
        s->twoD_destination = value;
        break;
    case SM501_2D_DIMENSION:
        s->twoD_dimension = value;
        break;
    case SM501_2D_CONTROL:
        s->twoD_control = value;

        /* do 2d operation if start flag is set. */
        if (value & 0x80000000) {
            sm501_2d_operation(s);
            s->twoD_control &= ~0x80000000; /* start flag down */
        }

        break;
    case SM501_2D_PITCH:
        s->twoD_pitch = value;
        break;
    case SM501_2D_FOREGROUND:
        s->twoD_foreground = value;
        break;
    case SM501_2D_BACKGROUND:
        s->twoD_background = value;
        break;
    case SM501_2D_STRETCH:
        s->twoD_stretch = value;
        break;
    case SM501_2D_COLOR_COMPARE:
        s->twoD_color_compare = value;
        break;
    case SM501_2D_COLOR_COMPARE_MASK:
        s->twoD_color_compare_mask = value;
        break;
    case SM501_2D_MASK:
        s->twoD_mask = value;
        break;
    case SM501_2D_CLIP_TL:
        s->twoD_clip_tl = value;
        break;
    case SM501_2D_CLIP_BR:
        s->twoD_clip_br = value;
        break;
    case SM501_2D_MONO_PATTERN_LOW:
        s->twoD_mono_pattern_low = value;
        break;
    case SM501_2D_MONO_PATTERN_HIGH:
        s->twoD_mono_pattern_high = value;
        break;
    case SM501_2D_WINDOW_WIDTH:
        s->twoD_window_width = value;
        break;
    case SM501_2D_SOURCE_BASE:
        s->twoD_source_base = value;
        break;
    case SM501_2D_DESTINATION_BASE:
        s->twoD_destination_base = value;
        break;
    case SM501_2D_ALPHA:
        s->twoD_alpha = value;
        break;
    case SM501_2D_WRAP:
        s->twoD_wrap = value;
        break;
    case SM501_2D_STATUS:
        /* ignored, writing 0 should clear interrupt status */
        break;
    default:
        printf("sm501 2d engine : not implemented register write."
               " addr=%x, val=%x\n", (int)addr, (unsigned)value);
        abort();
    }
}

static const MemoryRegionOps sm501_2d_engine_ops = {
    .read = sm501_2d_engine_read,
    .write = sm501_2d_engine_write,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

/* draw line functions for all console modes */

typedef void draw_line_func(uint8_t *d, const uint8_t *s,
                            int width, const uint32_t *pal);

typedef void draw_hwc_line_func(uint8_t *d, const uint8_t *s,
                                int width, const uint8_t *palette,
                                int c_x, int c_y);

#define DEPTH 8
#include "sm501_template.h"

#define DEPTH 15
#include "sm501_template.h"

#define BGR_FORMAT
#define DEPTH 15
#include "sm501_template.h"

#define DEPTH 16
#include "sm501_template.h"

#define BGR_FORMAT
#define DEPTH 16
#include "sm501_template.h"

#define DEPTH 32
#include "sm501_template.h"

#define BGR_FORMAT
#define DEPTH 32
#include "sm501_template.h"

static draw_line_func *draw_line8_funcs[] = {
    draw_line8_8,
    draw_line8_15,
    draw_line8_16,
    draw_line8_32,
    draw_line8_32bgr,
    draw_line8_15bgr,
    draw_line8_16bgr,
};

static draw_line_func *draw_line16_funcs[] = {
    draw_line16_8,
    draw_line16_15,
    draw_line16_16,
    draw_line16_32,
    draw_line16_32bgr,
    draw_line16_15bgr,
    draw_line16_16bgr,
};

static draw_line_func *draw_line32_funcs[] = {
    draw_line32_8,
    draw_line32_15,
    draw_line32_16,
    draw_line32_32,
    draw_line32_32bgr,
    draw_line32_15bgr,
    draw_line32_16bgr,
};

static draw_hwc_line_func *draw_hwc_line_funcs[] = {
    draw_hwc_line_8,
    draw_hwc_line_15,
    draw_hwc_line_16,
    draw_hwc_line_32,
    draw_hwc_line_32bgr,
    draw_hwc_line_15bgr,
    draw_hwc_line_16bgr,
};

static inline int get_depth_index(DisplaySurface *surface)
{
    switch (surface_bits_per_pixel(surface)) {
    default:
    case 8:
        return 0;
    case 15:
        return 1;
    case 16:
        return 2;
    case 32:
        if (is_surface_bgr(surface)) {
            return 4;
        } else {
            return 3;
        }
    }
}

static void sm501_update_display(void *opaque)
{
    SM501State *s = (SM501State *)opaque;
    DisplaySurface *surface = qemu_console_surface(s->con);
    DirtyBitmapSnapshot *snap;
    int y, c_x = 0, c_y = 0;
    int crt = (s->dc_crt_control & SM501_DC_CRT_CONTROL_SEL) ? 1 : 0;
    int width = get_width(s, crt);
    int height = get_height(s, crt);
    int src_bpp = get_bpp(s, crt);
    int dst_bpp = surface_bytes_per_pixel(surface);
    int dst_depth_index = get_depth_index(surface);
    draw_line_func *draw_line = NULL;
    draw_hwc_line_func *draw_hwc_line = NULL;
    int full_update = 0;
    int y_start = -1;
    ram_addr_t offset;
    uint32_t *palette;
    uint8_t hwc_palette[3 * 3];
    uint8_t *hwc_src = NULL;

    if (!((crt ? s->dc_crt_control : s->dc_panel_control)
          & SM501_DC_CRT_CONTROL_ENABLE)) {
        return;
    }

    palette = (uint32_t *)(crt ? &s->dc_palette[SM501_DC_CRT_PALETTE -
                                                SM501_DC_PANEL_PALETTE]
                               : &s->dc_palette[0]);

    /* choose draw_line function */
    switch (src_bpp) {
    case 1:
        draw_line = draw_line8_funcs[dst_depth_index];
        break;
    case 2:
        draw_line = draw_line16_funcs[dst_depth_index];
        break;
    case 4:
        draw_line = draw_line32_funcs[dst_depth_index];
        break;
    default:
        printf("sm501 update display : invalid control register value.\n");
        abort();
        break;
    }

    /* set up to draw hardware cursor */
    if (is_hwc_enabled(s, crt)) {
        /* choose cursor draw line function */
        draw_hwc_line = draw_hwc_line_funcs[dst_depth_index];
        hwc_src = get_hwc_address(s, crt);
        c_x = get_hwc_x(s, crt);
        c_y = get_hwc_y(s, crt);
        get_hwc_palette(s, crt, hwc_palette);
    }

    /* adjust console size */
    if (s->last_width != width || s->last_height != height) {
        qemu_console_resize(s->con, width, height);
        surface = qemu_console_surface(s->con);
        s->last_width = width;
        s->last_height = height;
        full_update = 1;
    }

    /* someone else requested a full update */
    if (s->do_full_update) {
        s->do_full_update = false;
        full_update = 1;
    }

    /* draw each line according to conditions */
    offset = get_fb_addr(s, crt);
    snap = memory_region_snapshot_and_clear_dirty(&s->local_mem_region,
              offset, width * height * src_bpp, DIRTY_MEMORY_VGA);
    for (y = 0; y < height; y++, offset += width * src_bpp) {
        int update, update_hwc;

        /* check if hardware cursor is enabled and we're within its range */
        update_hwc = draw_hwc_line && c_y <= y && y < c_y + SM501_HWC_HEIGHT;
        update = full_update || update_hwc;
        /* check dirty flags for each line */
        update |= memory_region_snapshot_get_dirty(&s->local_mem_region, snap,
                                                   offset, width * src_bpp);

        /* draw line and change status */
        if (update) {
            uint8_t *d = surface_data(surface);
            d +=  y * width * dst_bpp;

            /* draw graphics layer */
            draw_line(d, s->local_mem + offset, width, palette);

            /* draw hardware cursor */
            if (update_hwc) {
                draw_hwc_line(d, hwc_src, width, hwc_palette, c_x, y - c_y);
            }

            if (y_start < 0) {
                y_start = y;
            }
        } else {
            if (y_start >= 0) {
                /* flush to display */
                dpy_gfx_update(s->con, 0, y_start, width, y - y_start);
                y_start = -1;
            }
        }
    }
    g_free(snap);

    /* complete flush to display */
    if (y_start >= 0) {
        dpy_gfx_update(s->con, 0, y_start, width, y - y_start);
    }
}

static const GraphicHwOps sm501_ops = {
    .gfx_update  = sm501_update_display,
};

static void sm501_reset(SM501State *s)
{
    s->system_control = 0x00100000; /* 2D engine FIFO empty */
    /* Bits 17 (SH), 7 (CDR), 6:5 (Test), 2:0 (Bus) are all supposed
     * to be determined at reset by GPIO lines which set config bits.
     * We hardwire them:
     *  SH = 0 : Hitachi Ready Polarity == Active Low
     *  CDR = 0 : do not reset clock divider
     *  TEST = 0 : Normal mode (not testing the silicon)
     *  BUS = 0 : Hitachi SH3/SH4
     */
    s->misc_control = SM501_MISC_DAC_POWER;
    s->gpio_31_0_control = 0;
    s->gpio_63_32_control = 0;
    s->dram_control = 0;
    s->arbitration_control = 0x05146732;
    s->irq_mask = 0;
    s->misc_timing = 0;
    s->power_mode_control = 0;
    s->i2c_byte_count = 0;
    s->i2c_status = 0;
    s->i2c_addr = 0;
    memset(s->i2c_data, 0, 16);
    s->dc_panel_control = 0x00010000; /* FIFO level 3 */
    s->dc_video_control = 0;
    s->dc_crt_control = 0x00010000;
    s->twoD_source = 0;
    s->twoD_destination = 0;
    s->twoD_dimension = 0;
    s->twoD_control = 0;
    s->twoD_pitch = 0;
    s->twoD_foreground = 0;
    s->twoD_background = 0;
    s->twoD_stretch = 0;
    s->twoD_color_compare = 0;
    s->twoD_color_compare_mask = 0;
    s->twoD_mask = 0;
    s->twoD_clip_tl = 0;
    s->twoD_clip_br = 0;
    s->twoD_mono_pattern_low = 0;
    s->twoD_mono_pattern_high = 0;
    s->twoD_window_width = 0;
    s->twoD_source_base = 0;
    s->twoD_destination_base = 0;
    s->twoD_alpha = 0;
    s->twoD_wrap = 0;
}

static void sm501_init(SM501State *s, DeviceState *dev,
                       uint32_t local_mem_bytes)
{
    s->local_mem_size_index = get_local_mem_size_index(local_mem_bytes);
    SM501_DPRINTF("sm501 local mem size=%x. index=%d\n", get_local_mem_size(s),
                  s->local_mem_size_index);

    /* local memory */
    memory_region_init_ram(&s->local_mem_region, OBJECT(dev), "sm501.local",
                           get_local_mem_size(s), &error_fatal);
    memory_region_set_log(&s->local_mem_region, true, DIRTY_MEMORY_VGA);
    s->local_mem = memory_region_get_ram_ptr(&s->local_mem_region);

    /* i2c */
    s->i2c_bus = i2c_init_bus(dev, "sm501.i2c");
    /* ddc */
    I2CDDCState *ddc = I2CDDC(qdev_create(BUS(s->i2c_bus), TYPE_I2CDDC));
    i2c_set_slave_address(I2C_SLAVE(ddc), 0x50);

    /* mmio */
    memory_region_init(&s->mmio_region, OBJECT(dev), "sm501.mmio", MMIO_SIZE);
    memory_region_init_io(&s->system_config_region, OBJECT(dev),
                          &sm501_system_config_ops, s,
                          "sm501-system-config", 0x6c);
    memory_region_add_subregion(&s->mmio_region, SM501_SYS_CONFIG,
                                &s->system_config_region);
    memory_region_init_io(&s->i2c_region, OBJECT(dev), &sm501_i2c_ops, s,
                          "sm501-i2c", 0x14);
    memory_region_add_subregion(&s->mmio_region, SM501_I2C, &s->i2c_region);
    memory_region_init_io(&s->disp_ctrl_region, OBJECT(dev),
                          &sm501_disp_ctrl_ops, s,
                          "sm501-disp-ctrl", 0x1000);
    memory_region_add_subregion(&s->mmio_region, SM501_DC,
                                &s->disp_ctrl_region);
    memory_region_init_io(&s->twoD_engine_region, OBJECT(dev),
                          &sm501_2d_engine_ops, s,
                          "sm501-2d-engine", 0x54);
    memory_region_add_subregion(&s->mmio_region, SM501_2D_ENGINE,
                                &s->twoD_engine_region);

    /* create qemu graphic console */
    s->con = graphic_console_init(DEVICE(dev), 0, &sm501_ops, s);
}

static const VMStateDescription vmstate_sm501_state = {
    .name = "sm501-state",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(local_mem_size_index, SM501State),
        VMSTATE_UINT32(system_control, SM501State),
        VMSTATE_UINT32(misc_control, SM501State),
        VMSTATE_UINT32(gpio_31_0_control, SM501State),
        VMSTATE_UINT32(gpio_63_32_control, SM501State),
        VMSTATE_UINT32(dram_control, SM501State),
        VMSTATE_UINT32(arbitration_control, SM501State),
        VMSTATE_UINT32(irq_mask, SM501State),
        VMSTATE_UINT32(misc_timing, SM501State),
        VMSTATE_UINT32(power_mode_control, SM501State),
        VMSTATE_UINT32(uart0_ier, SM501State),
        VMSTATE_UINT32(uart0_lcr, SM501State),
        VMSTATE_UINT32(uart0_mcr, SM501State),
        VMSTATE_UINT32(uart0_scr, SM501State),
        VMSTATE_UINT8_ARRAY(dc_palette, SM501State, DC_PALETTE_ENTRIES),
        VMSTATE_UINT32(dc_panel_control, SM501State),
        VMSTATE_UINT32(dc_panel_panning_control, SM501State),
        VMSTATE_UINT32(dc_panel_fb_addr, SM501State),
        VMSTATE_UINT32(dc_panel_fb_offset, SM501State),
        VMSTATE_UINT32(dc_panel_fb_width, SM501State),
        VMSTATE_UINT32(dc_panel_fb_height, SM501State),
        VMSTATE_UINT32(dc_panel_tl_location, SM501State),
        VMSTATE_UINT32(dc_panel_br_location, SM501State),
        VMSTATE_UINT32(dc_panel_h_total, SM501State),
        VMSTATE_UINT32(dc_panel_h_sync, SM501State),
        VMSTATE_UINT32(dc_panel_v_total, SM501State),
        VMSTATE_UINT32(dc_panel_v_sync, SM501State),
        VMSTATE_UINT32(dc_panel_hwc_addr, SM501State),
        VMSTATE_UINT32(dc_panel_hwc_location, SM501State),
        VMSTATE_UINT32(dc_panel_hwc_color_1_2, SM501State),
        VMSTATE_UINT32(dc_panel_hwc_color_3, SM501State),
        VMSTATE_UINT32(dc_video_control, SM501State),
        VMSTATE_UINT32(dc_crt_control, SM501State),
        VMSTATE_UINT32(dc_crt_fb_addr, SM501State),
        VMSTATE_UINT32(dc_crt_fb_offset, SM501State),
        VMSTATE_UINT32(dc_crt_h_total, SM501State),
        VMSTATE_UINT32(dc_crt_h_sync, SM501State),
        VMSTATE_UINT32(dc_crt_v_total, SM501State),
        VMSTATE_UINT32(dc_crt_v_sync, SM501State),
        VMSTATE_UINT32(dc_crt_hwc_addr, SM501State),
        VMSTATE_UINT32(dc_crt_hwc_location, SM501State),
        VMSTATE_UINT32(dc_crt_hwc_color_1_2, SM501State),
        VMSTATE_UINT32(dc_crt_hwc_color_3, SM501State),
        VMSTATE_UINT32(twoD_source, SM501State),
        VMSTATE_UINT32(twoD_destination, SM501State),
        VMSTATE_UINT32(twoD_dimension, SM501State),
        VMSTATE_UINT32(twoD_control, SM501State),
        VMSTATE_UINT32(twoD_pitch, SM501State),
        VMSTATE_UINT32(twoD_foreground, SM501State),
        VMSTATE_UINT32(twoD_background, SM501State),
        VMSTATE_UINT32(twoD_stretch, SM501State),
        VMSTATE_UINT32(twoD_color_compare, SM501State),
        VMSTATE_UINT32(twoD_color_compare_mask, SM501State),
        VMSTATE_UINT32(twoD_mask, SM501State),
        VMSTATE_UINT32(twoD_clip_tl, SM501State),
        VMSTATE_UINT32(twoD_clip_br, SM501State),
        VMSTATE_UINT32(twoD_mono_pattern_low, SM501State),
        VMSTATE_UINT32(twoD_mono_pattern_high, SM501State),
        VMSTATE_UINT32(twoD_window_width, SM501State),
        VMSTATE_UINT32(twoD_source_base, SM501State),
        VMSTATE_UINT32(twoD_destination_base, SM501State),
        VMSTATE_UINT32(twoD_alpha, SM501State),
        VMSTATE_UINT32(twoD_wrap, SM501State),
        /* Added in version 2 */
        VMSTATE_UINT8(i2c_byte_count, SM501State),
        VMSTATE_UINT8(i2c_status, SM501State),
        VMSTATE_UINT8(i2c_addr, SM501State),
        VMSTATE_UINT8_ARRAY(i2c_data, SM501State, 16),
        VMSTATE_END_OF_LIST()
     }
};

#define TYPE_SYSBUS_SM501 "sysbus-sm501"
#define SYSBUS_SM501(obj) \
    OBJECT_CHECK(SM501SysBusState, (obj), TYPE_SYSBUS_SM501)

typedef struct {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/
    SM501State state;
    uint32_t vram_size;
    uint32_t base;
    void *chr_state;
} SM501SysBusState;

static void sm501_realize_sysbus(DeviceState *dev, Error **errp)
{
    SM501SysBusState *s = SYSBUS_SM501(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    DeviceState *usb_dev;

    sm501_init(&s->state, dev, s->vram_size);
    if (get_local_mem_size(&s->state) != s->vram_size) {
        error_setg(errp, "Invalid VRAM size, nearest valid size is %" PRIu32,
                   get_local_mem_size(&s->state));
        return;
    }
    sysbus_init_mmio(sbd, &s->state.local_mem_region);
    sysbus_init_mmio(sbd, &s->state.mmio_region);

    /* bridge to usb host emulation module */
    usb_dev = qdev_create(NULL, "sysbus-ohci");
    qdev_prop_set_uint32(usb_dev, "num-ports", 2);
    qdev_prop_set_uint64(usb_dev, "dma-offset", s->base);
    qdev_init_nofail(usb_dev);
    memory_region_add_subregion(&s->state.mmio_region, SM501_USB_HOST,
                       sysbus_mmio_get_region(SYS_BUS_DEVICE(usb_dev), 0));
    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(usb_dev));

    /* bridge to serial emulation module */
    if (s->chr_state) {
        serial_mm_init(&s->state.mmio_region, SM501_UART0, 2,
                       NULL, /* TODO : chain irq to IRL */
                       115200, s->chr_state, DEVICE_LITTLE_ENDIAN);
    }
}

static Property sm501_sysbus_properties[] = {
    DEFINE_PROP_UINT32("vram-size", SM501SysBusState, vram_size, 0),
    DEFINE_PROP_UINT32("base", SM501SysBusState, base, 0),
    DEFINE_PROP_PTR("chr-state", SM501SysBusState, chr_state),
    DEFINE_PROP_END_OF_LIST(),
};

static void sm501_reset_sysbus(DeviceState *dev)
{
    SM501SysBusState *s = SYSBUS_SM501(dev);
    sm501_reset(&s->state);
}

static const VMStateDescription vmstate_sm501_sysbus = {
    .name = TYPE_SYSBUS_SM501,
    .version_id = 2,
    .minimum_version_id = 2,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT(state, SM501SysBusState, 1,
                       vmstate_sm501_state, SM501State),
        VMSTATE_END_OF_LIST()
     }
};

static void sm501_sysbus_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = sm501_realize_sysbus;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    dc->desc = "SM501 Multimedia Companion";
    dc->props = sm501_sysbus_properties;
    dc->reset = sm501_reset_sysbus;
    dc->vmsd = &vmstate_sm501_sysbus;
    /* Note: pointer property "chr-state" may remain null, thus
     * no need for dc->user_creatable = false;
     */
}

static const TypeInfo sm501_sysbus_info = {
    .name          = TYPE_SYSBUS_SM501,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SM501SysBusState),
    .class_init    = sm501_sysbus_class_init,
};

#define TYPE_PCI_SM501 "sm501"
#define PCI_SM501(obj) OBJECT_CHECK(SM501PCIState, (obj), TYPE_PCI_SM501)

typedef struct {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/
    SM501State state;
    uint32_t vram_size;
} SM501PCIState;

static void sm501_realize_pci(PCIDevice *dev, Error **errp)
{
    SM501PCIState *s = PCI_SM501(dev);

    sm501_init(&s->state, DEVICE(dev), s->vram_size);
    if (get_local_mem_size(&s->state) != s->vram_size) {
        error_setg(errp, "Invalid VRAM size, nearest valid size is %" PRIu32,
                   get_local_mem_size(&s->state));
        return;
    }
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->state.local_mem_region);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->state.mmio_region);
}

static Property sm501_pci_properties[] = {
    DEFINE_PROP_UINT32("vram-size", SM501PCIState, vram_size, 64 * MiB),
    DEFINE_PROP_END_OF_LIST(),
};

static void sm501_reset_pci(DeviceState *dev)
{
    SM501PCIState *s = PCI_SM501(dev);
    sm501_reset(&s->state);
    /* Bits 2:0 of misc_control register is 001 for PCI */
    s->state.misc_control |= 1;
}

static const VMStateDescription vmstate_sm501_pci = {
    .name = TYPE_PCI_SM501,
    .version_id = 2,
    .minimum_version_id = 2,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, SM501PCIState),
        VMSTATE_STRUCT(state, SM501PCIState, 1,
                       vmstate_sm501_state, SM501State),
        VMSTATE_END_OF_LIST()
     }
};

static void sm501_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = sm501_realize_pci;
    k->vendor_id = PCI_VENDOR_ID_SILICON_MOTION;
    k->device_id = PCI_DEVICE_ID_SM501;
    k->class_id = PCI_CLASS_DISPLAY_OTHER;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    dc->desc = "SM501 Display Controller";
    dc->props = sm501_pci_properties;
    dc->reset = sm501_reset_pci;
    dc->hotpluggable = false;
    dc->vmsd = &vmstate_sm501_pci;
}

static const TypeInfo sm501_pci_info = {
    .name          = TYPE_PCI_SM501,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(SM501PCIState),
    .class_init    = sm501_pci_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void sm501_register_types(void)
{
    type_register_static(&sm501_sysbus_info);
    type_register_static(&sm501_pci_info);
}

type_init(sm501_register_types)

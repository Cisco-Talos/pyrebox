/*
 * QEMU SDL display driver
 *
 * Copyright (c) 2003 Fabrice Bellard
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
/* Ported SDL 1.2 code to 2.0 by Dave Airlie. */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "ui/console.h"
#include "ui/input.h"
#include "ui/sdl2.h"
#include "sysemu/sysemu.h"

void sdl2_process_key(struct sdl2_console *scon,
                      SDL_KeyboardEvent *ev)
{
    int qcode;
    QemuConsole *con = scon->dcl.con;

    if (ev->keysym.scancode >= qemu_input_map_usb_to_qcode_len) {
        return;
    }
    qcode = qemu_input_map_usb_to_qcode[ev->keysym.scancode];
    qkbd_state_key_event(scon->kbd, qcode, ev->type == SDL_KEYDOWN);

    if (!qemu_console_is_graphic(con)) {
        bool ctrl = qkbd_state_modifier_get(scon->kbd, QKBD_MOD_CTRL);
        if (ev->type == SDL_KEYDOWN) {
            switch (qcode) {
            case Q_KEY_CODE_RET:
                kbd_put_keysym_console(con, '\n');
                break;
            default:
                kbd_put_qcode_console(con, qcode, ctrl);
                break;
            }
        }
    }
}

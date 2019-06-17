/*-------------------------------------------------------------------------------

   Copyright (C) 2019 Cisco Talos Security Intelligence and Research Group

   PyREBox: Python scriptable Reverse Engineering Sandbox 
   Author: Xabier Ugarte-Pedrero 
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301, USA.
   
-------------------------------------------------------------------------------*/

#ifndef QEMU_GLUE_UI_H
#define QEMU_GLUE_UI_H

void pyrebox_mouse_move(int dx, int dy, int dz);
void pyrebox_mouse_button(int button_state);
void pyrebox_sendkeys(const char* keys, int hold_time);
void pyrebox_screendump(const char* filename);

#endif


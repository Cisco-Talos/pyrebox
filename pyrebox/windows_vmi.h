/*-------------------------------------------------------------------------------

   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group

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

#ifndef WINDOWS_VMI_H
#define WINDOWS_VMI_H

#define SELFPCR_OFFSET_32 0x1c
#define SELFPCR_OFFSET_64 0x18
#define PS_ACTIVE_PROCESS_HEAD_OFFSET 0x50
#define PROCESS_NAME_SIZE 15
#define EXIT_TIME_SIZE 0x8

typedef enum eprocess_offset_index{
    PS_ACTIVE_LIST = 0,
    PID,
    PPID,
    NAME,
    PGD,
    EXIT_TIME,
    LastOffset
} offset_index_t;

extern unsigned int eprocess_offsets[LimitWindows][LastOffset];

void windows_vmi_init(os_index_t vol_profile);
void windows_vmi_tlb_callback(pyrebox_target_ulong pgd, os_index_t os_index);
void windows_vmi_context_change_callback(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd, os_index_t os_index);

#endif //WINDOWS_VMI_H

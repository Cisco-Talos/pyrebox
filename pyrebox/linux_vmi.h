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

#ifndef LINUX_VMI_H
#define LINUX_VMI_H

#include "linux_vmi_config.h"

void linux_vmi_init(os_index_t os_index);
void linux_vmi_tlb_callback(pyrebox_target_ulong pgd, os_index_t os_index);
void linux_vmi_context_change_callback(pyrebox_target_ulong old_pgd,pyrebox_target_ulong new_pgd, os_index_t os_index);
void initialize_init_task(pyrebox_target_ulong pgd);

#endif //LINUX_VMI_H

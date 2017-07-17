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

#ifndef PROCESS_MGR_H
#define PROCESS_MGR_H

#ifdef __cplusplus
extern "C" {
#endif
int add_monitored_process(pyrebox_target_ulong pgd);
int remove_monitored_process(pyrebox_target_ulong pgd,int force);
int is_monitored_process(pyrebox_target_ulong pgd);
void clear_monitored_processes(void);
int nb_monitored_processes(void);
#ifdef __cplusplus
};
#endif

#ifdef __cplusplus
//CPP class definitions
#endif

#endif

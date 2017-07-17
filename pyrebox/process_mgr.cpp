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

#include <Python.h>
#include <map>
#include <string>

#include "qemu_glue.h"
#include "process_mgr.h"
extern "C"{
    #include "qemu_glue_callbacks_flush.h"
}

using namespace std;

static map<pyrebox_target_ulong,unsigned int> monitored_processes;

extern "C"{

int add_monitored_process(pyrebox_target_ulong pgd){
    map<pyrebox_target_ulong,unsigned int>::iterator it = monitored_processes.find(pgd);
    if(it != monitored_processes.end()) {
        monitored_processes[pgd] = ++(it->second);
        return 1;
    } else {
        monitored_processes[pgd] = 1;
        //Perform flush, because we will need to insert callbacks now
        pyrebox_flush_tb();
        return 1;
    }
}
int remove_monitored_process(pyrebox_target_ulong pgd,int force){
    map<pyrebox_target_ulong,unsigned int>::iterator it = monitored_processes.find(pgd);
    if(it != monitored_processes.end()) {
        unsigned int count = it->second;
        if (count > 0){
            count -= 1;
        }
        if (count == 0 || force){
            monitored_processes.erase(pgd);
            //Perform flush, because we will not need to insert callbacks now
            pyrebox_flush_tb();
        } else {
            monitored_processes[pgd] = count;
        }
        return 1;
    }
    else
    {
        //Return false since the process was not monitored 
        return 0;
    }
}
int is_monitored_process(pyrebox_target_ulong pgd){
    return (monitored_processes.find(pgd) != monitored_processes.end());
}

void clear_monitored_processes(){
    monitored_processes.clear();
}

int nb_monitored_processes(){
    return (monitored_processes.size());
}

};

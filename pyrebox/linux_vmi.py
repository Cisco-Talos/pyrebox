# -------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------

from utils import pp_error


def linux_get_offsets():
    from utils import ConfigurationManager as conf_m
    import volatility.obj as obj
    import volatility.registry as registry
    try:
        profs = registry.get_plugin_classes(obj.Profile)
        profile = profs[conf_m.conf.vol_profile]()
        init_task_offset = profile.get_symbol("init_task")
        comm_offset = profile.get_obj_offset("task_struct", "comm")
        pid_offset = profile.get_obj_offset("task_struct", "pid")
        tasks_offset = profile.get_obj_offset("task_struct", "tasks")
        mm_offset = profile.get_obj_offset("task_struct", "mm")
        pgd_offset = profile.get_obj_offset("mm_struct", "pgd")
        parent_offset = profile.get_obj_offset("task_struct", "parent")
        exit_state_offset = profile.get_obj_offset("task_struct", "exit_state")

        # new process
        proc_exec_connector_offset = profile.get_symbol("proc_exec_connector")
        # new kernel module
        trim_init_extable_offset = profile.get_symbol("trim_init_extable")
        # process exit
        proc_exit_connector_offset = profile.get_symbol("proc_exit_connector")

        return (long(init_task_offset),
                long(comm_offset),
                long(pid_offset),
                long(tasks_offset),
                long(mm_offset),
                long(pgd_offset),
                long(parent_offset),
                long(exit_state_offset),
                long(proc_exec_connector_offset),
                long(trim_init_extable_offset),
                long(proc_exit_connector_offset))

    except Exception as e:
        pp_error("Could not retrieve symbols for profile initialization %s" % str(e))
        return None


def linux_init_address_space():
    from utils import ConfigurationManager as conf_m
    import volatility.utils as utils
    try:
        config = conf_m.vol_conf
        try:
            addr_space = utils.load_as(config)
        except BaseException as e:
            # Return silently
            print (str(e))
            conf_m.addr_space = None
            return False
        conf_m.addr_space = addr_space
        return True
    except Exception as e:
        pp_error("Could not load volatility address space: %s" % str(e))

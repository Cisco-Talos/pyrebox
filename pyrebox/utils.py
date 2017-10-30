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

import utils_print
import fnmatch

# Print function wrappers


def pp_print(f, *args):
    return utils_print.prnt("%s" % (f % args))


def pp_debug(f, *args):
    return utils_print.debug("%s" % (f % args))


def pp_warning(f, *args):
    return utils_print.warning("%s" % (f % args))


def pp_error(f, *args):
    return utils_print.error("%s" % (f % args))


class ConfigurationManager:
    # Class variables
    # Volatility configuration object
    vol_conf = None
    # Pre initialized address space for volatility
    addr_space = None
    # Path to volatility module
    volatility_path = None
    # Platform (e.g.: i386-softmmu, x86_64-softmmu)
    platform = None
    # String containing the volatility profile name as
    # declared in pyrebox.conf
    vol_profile = None
    # Agent file name
    agent_filename = None
    # Agent buffer offset and size
    agent_buffer_offset = None
    agent_buffer_size = None
    # config object
    config = None

    def __init__(self):
        ConfigurationManager.volatility_path = None
        ConfigurationManager.vol_profile = None
        ConfigurationManager.platform = None
        ConfigurationManager.vol_conf = None
        ConfigurationManager.addr_space = None
        ConfigurationManager.agent_filename = None
        ConfigurationManager.agent_buffer_offset = None
        ConfigurationManager.agent_buffer_size = None
        ConfigurationManager.config = None


def get_addr_space(pgd=None):
    if pgd is not None:
        ConfigurationManager.addr_space.dtb = pgd
    return ConfigurationManager.addr_space


def find_procs(param):
    import api
    nb = None
    name = None
    try:
        nb = int(param, 16)
    except BaseException:
        name = param
    proc_list = api.get_process_list()
    found = []
    for proc in proc_list:
        pid = proc["pid"]
        pgd = proc["pgd"]
        pname = proc["name"]
        # k_addr = proc["kaddr"]
        if (nb is not None and (nb == pid or nb == pgd)) or (
                name is not None and (fnmatch.fnmatch(pname, name) or name in pname)):
            found.append((pid, pgd, pname))
    return found

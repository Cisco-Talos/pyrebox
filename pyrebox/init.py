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

import os.path
import os
from prettytable import PrettyTable

import sys
import ConfigParser
import traceback
from utils import ConfigurationManager as conf_m
from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error

import functools


#   Python module initialization routine
#   ====================================

# Module handle incremental counter, start at 0x1
MODULE_COUNTER = 0x1

modules = {}


class ConfigManager:
    def __init__(self, volatility_path, vol_profile, platform):
        self.volatility_path = volatility_path
        self.vol_profile = vol_profile
        self.platform = platform


def import_module(module_name):
    global MODULE_COUNTER
    import api_internal
    from ipython_shell import add_command
    try:
        already_imported = False
        for mod in modules:
            if module_name == modules[mod][0]:
                already_imported = True
                break
        if not already_imported:
            pp_print("[*]  Importing %s\n" % module_name)
            mod = __import__(module_name, fromlist=[''])
            mod.initialize_callbacks(
                MODULE_COUNTER, functools.partial(
                    api_internal.print_internal, module_name))
            # Add commands declared by the module
            for element in dir(mod):
                if element.startswith("do_"):
                    add_command(element[3:], getattr(mod, element))
            modules[MODULE_COUNTER] = (module_name, mod)
            MODULE_COUNTER += 1
        else:
            pp_warning("[*]  Module %s already imported\n" % module_name)
    except Exception as e:
        pp_error("[!] Could not initialize python module due to exception\n")
        pp_error("    %s\n" % str(e))
        return


def unload_module(mod):
    from ipython_shell import remove_command
    if isinstance(mod, int) and mod in modules:
        pp_print("[*]  Unloading %s\n" % modules[mod][0])
        # Add commands declared by the module
        for element in dir(modules[mod][1]):
            if element.startswith("do_"):
                remove_command(element[3:])
        modules[mod][1].clean()
        # Remove module from list
        del modules[mod]
    else:
        pp_warning("[*]  Module not loaded!\n")


def list_modules():
    t = PrettyTable(["Hdl", "Module name"])
    for mod in modules:
        t.add_row([mod, modules[mod][0]])
    pp_print(str(t) + "\n")


def pyrebox_shell():
    finished = False
    while not finished:
        try:
            from ipython_shell import start_shell
            start_shell()
            finished = True
        except Exception as e:
            pp_error(str(e) + "\n")
            traceback.print_exc(file=sys.stdout)


def pyrebox_ipython_shell():
    finished = False
    while not finished:
        try:
            from ipython_shell import start_shell
            start_shell()
            finished = True
        except Exception as e:
            pp_error(str(e) + "\n")
            traceback.print_exc(file=sys.stdout)


def init_volatility(conf):
    import volatility.conf as volconf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.addrspace as addrspace

    if hasattr(volconf, "PyREBoxVolatility"):
        registry.PluginImporter()
        vol_config = volconf.ConfObject()
        registry.register_global_options(vol_config, commands.Command)
        registry.register_global_options(vol_config, addrspace.BaseAddressSpace)
        vol_config.PROFILE = conf.vol_profile

        # Set global volatility configuration
        conf_m.vol_conf = vol_config
        return True
    else:
        pp_error("""The imported volatility version is not appropriate for PyREBox:
    * Your local volatility instalation may be in conflict with PyREBox's volatility installation...
      ... set up a virtual env to avoid the conflict (see installation instructions).
    * PyREBox's volatility version was not properly installed or configured...
      ... you rebuild it running: $./build.sh --rebuild_volatility
    * You have a virtual env for PyREBox's python dependencies, and you forgot to activate it!
      ... you know what to do!\n""")
        return False


def init(platform, root_path, volatility_path):
    global conf
    try:
        # Just configure basic logging
        import logging
        logging.basicConfig()
        # Initialize stuff
        pp_debug("[*] Platform: %s\n" % platform)
        pp_debug("[*] Starting python module initialization\n")
        pp_debug("[*] Reading configuration\n")
        sys.settrace
        config = ConfigParser.RawConfigParser()
        if not os.path.isfile("pyrebox.conf"):
            pp_error("[!] Could not initialize pyrebox, pyrebox.conf file missing!\n")
            return None
        config.read('pyrebox.conf')
        vol_profile = config.get('VOL', 'profile')
        conf = ConfigManager(
            volatility_path=volatility_path,
            vol_profile=vol_profile,
            platform=platform)
        sys.path.append(conf.volatility_path)
        sys.path.append(root_path)
        sys.path.append(os.getcwd())
        # Set global configuration
        conf_m.conf = conf
        if not init_volatility(conf_m.conf):
            return None

        # Initialize the shell now
        from ipython_shell import initialize_shell
        initialize_shell()

        # Locate python modules that should be loaded by default
        for (module, enable) in config.items("MODULES"):
            if enable.strip().lower() == "true" or enable.strip().lower() == "yes":
                import_module(module)

        pp_debug("[*] Finished python module initialization\n")
        return vol_profile
    except Exception as e:
        # Do this to make sure we print the stack trace to help trouble-shooting
        traceback.print_exc()
        raise e

if __name__ == "__main__":
    pp_debug("\n[*] Loading python component initialization script\n")

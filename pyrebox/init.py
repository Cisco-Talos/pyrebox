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
MODULE_COUNTER = 0x0
modules = {}


class Module:
    def __init__(self, _id, module_name):
        self.__module_name = module_name
        self.__module = None
        self.__loaded = False
        self.__id = _id

    def get_module_name(self):
        return self.__module_name

    def is_loaded(self):
        return (self.__loaded)

    def load(self):
        import api_internal
        from ipython_shell import add_command
        pp_print("[*]  Loading python module %s\n" % self.__module_name)
        self.__module = __import__(self.__module_name, fromlist=[''])

        # Import other modules or plugins required by the module
        if hasattr(self.__module, "requirements"):
            for el in self.__module.requirements:
                import_module(el)

        self.__loaded = True
        self.__module.initialize_callbacks(self.__id,
                                           functools.partial(api_internal.print_internal, self.__module_name))

        # Add commands declared by the module
        for element in dir(self.__module):
            if element.startswith("do_"):
                add_command(element[3:], getattr(self.__module, element))

    def reload(self):
        import api_internal
        from ipython_shell import add_command
        if self.__module is not None:
            pp_print("[*]  Reloading python module %s\n" % self.__module_name)
            if self.__loaded is True:
                self.unload()
            reload(self.__module)
            # Add again commands and call initialize_callbacks:
            self.__module.initialize_callbacks(self.__id,
                                               functools.partial(api_internal.print_internal, self.__module_name))
            # Add commands declared by the module
            for element in dir(self.__module):
                if element.startswith("do_"):
                    add_command(element[3:], getattr(self.__module, element))
            self.__loaded = True
        else:
            pp_warning("[!] The module was not correctly imported!\n")

    def unload(self):
        from ipython_shell import remove_command
        if self.__loaded is True:
            pp_print("[*]  Unloading %s\n" % self.__module_name)
            # Add commands declared by the module
            for element in dir(self.__module):
                if element.startswith("do_"):
                    remove_command(element[3:])
            self.__module.clean()
            self.__loaded = False
        else:
            pp_warning("[*]  Module %d is not loaded!\n" % self.__id)


def import_module(module_name):
    global MODULE_COUNTER
    try:
        already_imported = False
        for mod in modules:
            if modules[mod].get_module_name() == module_name:
                already_imported = True
                break
        if not already_imported:
            MODULE_COUNTER += 1
            modules[MODULE_COUNTER] = Module(MODULE_COUNTER, module_name)
            modules[MODULE_COUNTER].load()
        else:
            pp_warning("[*]  Module %s already imported, did you want to reload it instead?\n" % module_name)
    except Exception as e:
        pp_error("[!] Could not initialize python module due to exception\n")
        pp_error("    %s\n" % str(e))
        return


def reload_module(_id):
    try:
        if _id in modules:
            modules[_id].reload()
        else:
            pp_warning("[*]  The module number specified (%d) has not been imported\n" % _id)
    except Exception as e:
        pp_error("[!] Could not reload python module due to exception\n")
        pp_error("    %s\n" % str(e))
        return


def unload_module(_id):
    try:
        if _id in modules:
            modules[_id].unload()
        else:
            pp_warning("[*]  The module number specified (%d) has not been imported\n" % _id)
            pp_warning("[*]  Possible ids:")
            for i in modules:
                pp_warning("    %s - %s" % (str(i),str(type(i))))
    except Exception as e:
        pp_error("[!] Could not unload python module due to exception\n")
        pp_error("    %s\n" % str(e))
        return


def list_modules():
    t = PrettyTable(["Hdl", "Module name", "Loaded"])
    for mod in modules:
        t.add_row([mod, modules[mod].get_module_name(), "Yes" if modules[mod].is_loaded() else "No"])
    pp_print(str(t) + "\n")

def get_loaded_modules():
    mods = []
    for mod in modules:
        mods.append({"module_handle": mod, "module_name": modules[mod].get_module_name(), "is_loaded": modules[mod].is_loaded()})
    return mods

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


def init_volatility():
    import volatility.conf as volconf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.addrspace as addrspace

    if hasattr(volconf, "PyREBoxVolatility"):
        registry.PluginImporter()
        vol_config = volconf.ConfObject()
        registry.register_global_options(vol_config, commands.Command)
        registry.register_global_options(vol_config, addrspace.BaseAddressSpace)
        vol_config.PROFILE = conf_m.vol_profile

        # Set global volatility configuration
        conf_m.vol_conf = vol_config
        return True
    else:
        pp_error("""The imported volatility version is not appropriate for PyREBox:
    * Your local volatility installation may be in conflict with PyREBox's volatility installation...
      ... set up a virtual env to avoid the conflict (see installation instructions).
    * You have a virtual env for PyREBox's python dependencies, and you forgot to activate it!
      ... you know what to do!\n""")
        return False


def init(platform, root_path, volatility_path, conf_name):
    try:
        # Just configure basic logging
        import logging
        logging.basicConfig()
        # Initialize stuff
        pp_debug("[*] Platform: %s\n" % platform)
        pp_debug("[*] Starting python module initialization\n")
        pp_debug("[*] Reading configuration from '%s'\n" % (conf_name))
        sys.settrace
        config = ConfigParser.RawConfigParser()
        # Store configuration information in raw,
        # for plugins to be able to fetch it
        conf_m.config = config
        if not os.path.isfile(conf_name):
            pp_error("[!] Could not initialize pyrebox, conf file '%s' missing!\n" % (conf_name))
            return None
        config.read(conf_name)
        vol_profile = config.get('VOL', 'profile')
        # Set global configuration
        conf_m.volatility_path = volatility_path
        conf_m.vol_profile = vol_profile
        conf_m.platform = platform
        sys.path.append(volatility_path)
        sys.path.append(root_path)
        sys.path.append(os.getcwd())
        if not init_volatility():
            return None

        # Initialize the shell now
        from ipython_shell import initialize_shell
        initialize_shell()

        return vol_profile
    except Exception as e:
        # Do this to make sure we print the stack trace to help trouble-shooting
        traceback.print_exc()
        raise e


def init_plugins():
    try:
        pp_debug("[*] Initializing scripts...\n")
        # Locate python modules that should be loaded by default
        for (module, enable) in conf_m.config.items("MODULES"):
            if enable.strip().lower() == "true" or enable.strip().lower() == "yes":
                import_module(module)

        pp_debug("[*] Finished python module initialization\n")
        return True
    except Exception as e:
        # Do this to make sure we print the stack trace to help trouble-shooting
        traceback.print_exc()
        raise e


if __name__ == "__main__":
    pp_debug("\n[*] Loading python component initialization script\n")

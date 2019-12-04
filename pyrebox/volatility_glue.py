# -------------------------------------------------------------------------
#
#   Copyright (C) 2019 Cisco Talos Security Intelligence and Research Group
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
import logging
import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from volatility.framework import interfaces, constants
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist
from volatility.framework.plugins.windows.pyrebox import PyREBoxAccessWindows
from volatility.framework.plugins.linux.pyrebox import PyREBoxAccessLinux

OS_TYPE_WINDOWS = 0
OS_TYPE_LINUX = 1
OS_TYPE_MAC = 2

os_type = None
plugin_class = None
context = None
automagics = None
base_config_path= "plugins"
# Instance of the plugin
volatility_interface = None

vollog = logging.getLogger()

# Log everything:
#vollog.setLevel(1)

# Log only Warnings
vollog.setLevel(logging.WARNING)

# Trim the console down by default
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)
vollog.addHandler(console)

def initialize_volatility(plugin):
    global context
    global plugin_class
    global automagics

    plugin_class = plugin

    # First, check if we imported the correct volatility
    try:
        import volatility.framework.layers.pyrebox
    except Exception as e:
        print(e)
        raise ImportError("Imported wrong volatility version")

    volatility.framework.require_interface_version(1, 0, 0)
    # Set the PARALLELISM
    #constants.PARALLELISM = constants.Parallelism.Multiprocessing
    #constants.PARALLELISM = constants.Parallelism.Threading
    constants.PARALLELISM = constants.Parallelism.Off

    # Do the initialization
    ctx = contexts.Context()  # Construct a blank context
    failures = framework.import_files(volatility.plugins,
                                      True)  # Will not log as console's default level is WARNING

    automagics = automagic.available(ctx)
    # Initialize the list of plugins in case the plugin needs it 
    plugin_list = framework.list_plugins()

    single_location = "::PyREBox memory::" 
    ctx.config['automagic.LayerStacker.single_location'] = single_location

    automagics = automagic.choose_automagic(automagics, plugin_class)
    context = ctx

    return True

def construct_plugin(plugin_class, config_to_add):
    global context
    global automagics
    try:
        for k in config_to_add:
            context.config[k] = config_to_add[k]
        return plugins.construct_plugin(context, automagics, plugin_class, base_config_path, None, None)
    except Exception as e:
        pp_error("Exception constructing plugin: %s\n" % str(e))

def volatility_scan_ps_active_process_head(pgd):
    '''
        Scans the memory image, locates PsActiveProcessList,
        creates the process, and saves it.
    '''
    global context
    global plugin_class
    global automagics
    global base_config_path
    global volatility_interface

    errors = automagic.run(automagics, context, plugin_class, base_config_path)
    if len(errors) > 0:
        for error in errors:
            print(error)
        return None
    else:
        volatility_interface = plugins.construct_plugin(context, automagics, plugin_class, base_config_path, None, None)
        return volatility_interface.PsActiveProcessHeadAddr


def get_volatility_interface():
    global volatility_interface
    global context
    global plugin_class
    global automagics
    global base_config_path
    global os_type

    if volatility_interface is None and os_type == OS_TYPE_LINUX:
        errors = automagic.run(automagics, context, plugin_class, base_config_path)
        if len(errors) > 0:
            for error in errors:
                pp_error(error + "\n")
            return None
        else:
            volatility_interface = plugins.construct_plugin(context, automagics, plugin_class, base_config_path, None, None)

    return volatility_interface


def volatility_clear_lru_cache():
    '''
        Clear LRU caches for certain functions so that everything is re-read
    '''
    try:
        from volatility.framework.interfaces.layers import TranslationLayerInterface
        TranslationLayerInterface.read.cache_clear()

        from volatility.framework.symbols.windows.extensions import POOL_HEADER
        from volatility.framework.symbols.windows.extensions import MMVAD_SHORT
        POOL_HEADER._calculate_optional_header_lengths.cache_clear()
        MMVAD_SHORT.get_tag.cache_clear()

        from volatility.framework.contexts import SizedModule
        # We need to access the getter (fget) of the Hash property
        SizedModule.hash.fget.cache_clear()

        from volatility.framework.layers.linear import LinearlyMappedLayer
        LinearlyMappedLayer.read.cache_clear()

        from volatility.framework.layers.intel import Intel
        Intel._get_valid_table.cache_clear()
    except Exception as e:
        print(str(e))
    return None

def initialize_volatility_windows():
    global os_type
    os_type = OS_TYPE_WINDOWS
    return initialize_volatility(PyREBoxAccessWindows)

def initialize_volatility_linux():
    global os_type
    os_type = OS_TYPE_LINUX
    return initialize_volatility(PyREBoxAccessLinux)

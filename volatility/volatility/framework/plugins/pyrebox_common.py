import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from volatility.framework import interfaces, constants, objects
from volatility.framework.configuration import requirements
from volatility.plugins.windows import pslist
from volatility.framework.objects import StructType
from volatility.framework.objects import Pointer 

# A dictionary, PGD -> layer, to avoid creating
# layers repetetively, and avoiding the need to destroy them
process_layers = {}

def get_layer_from_task(plugin, task, pgd = None):
    global process_layers
    
    if pgd is None:
        pgd = plugin.get_pgd_from_task(task)
    if pgd is None:
        return None

    if pgd in process_layers:
        return process_layers[pgd]

    layer_name = task.add_process_layer()
    process_layers[pgd] = (layer_name, plugin.context.layers[layer_name])
    return process_layers[pgd]


def get_layer_from_pgd(plugin, pgd):
    global process_layers

    if pgd in process_layers:
        return process_layers[pgd]
    else:
        task = plugin.get_task_from_pgd(pgd)
        if task is None:
            return None

        return get_layer_from_task(plugin, task, pgd)

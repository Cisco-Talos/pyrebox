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
    conf = None
    vol_conf = None
    # Pre initialized address space for volatility
    addr_space = None

    def __init__(self, conf, vol_conf):
        ConfigurationManager.conf = conf
        ConfigurationManager.vol_conf = vol_conf
        ConfigurationManager.addr_space = None


def get_addr_space(pgd=None):
    if pgd is not None:
        ConfigurationManager.addr_space.dtb = pgd
    return ConfigurationManager.addr_space

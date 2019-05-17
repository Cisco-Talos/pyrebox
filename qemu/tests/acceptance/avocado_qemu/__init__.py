# Test class and utilities for functional tests
#
# Copyright (c) 2018 Red Hat, Inc.
#
# Author:
#  Cleber Rosa <crosa@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or
# later.  See the COPYING file in the top-level directory.

import os
import sys
import uuid

import avocado

SRC_ROOT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..')
sys.path.append(os.path.join(SRC_ROOT_DIR, 'python'))

from qemu import QEMUMachine

def is_readable_executable_file(path):
    return os.path.isfile(path) and os.access(path, os.R_OK | os.X_OK)


def pick_default_qemu_bin():
    """
    Picks the path of a QEMU binary, starting either in the current working
    directory or in the source tree root directory.
    """
    arch = os.uname()[4]
    qemu_bin_relative_path = os.path.join("%s-softmmu" % arch,
                                          "qemu-system-%s" % arch)
    if is_readable_executable_file(qemu_bin_relative_path):
        return qemu_bin_relative_path

    qemu_bin_from_src_dir_path = os.path.join(SRC_ROOT_DIR,
                                              qemu_bin_relative_path)
    if is_readable_executable_file(qemu_bin_from_src_dir_path):
        return qemu_bin_from_src_dir_path


class Test(avocado.Test):
    def setUp(self):
        self._vms = {}
        self.qemu_bin = self.params.get('qemu_bin',
                                        default=pick_default_qemu_bin())
        if self.qemu_bin is None:
            self.cancel("No QEMU binary defined or found in the source tree")

    def _new_vm(self, *args):
        vm = QEMUMachine(self.qemu_bin)
        if args:
            vm.add_args(*args)
        return vm

    @property
    def vm(self):
        return self.get_vm(name='default')

    def get_vm(self, *args, name=None):
        if not name:
            name = str(uuid.uuid4())
        if self._vms.get(name) is None:
            self._vms[name] = self._new_vm(*args)
        return self._vms[name]

    def tearDown(self):
        for vm in self._vms.values():
            vm.shutdown()

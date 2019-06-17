# -------------------------------------------------------------------------
#
#   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group
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


import idaapi
import idc
import pickle
import traceback
import os
import threading
import fnmatch
import functools

# =====================  QT imports  =====================
try:
    #   For IDA 6.8 and older using PySide
    # from PySide import QtGui, QtGui as QtWidgets, QtCore
    from PySide import QtGui, QtGui as QtWidgets
    from PySide.QtCore import Qt
except ImportError:
    try:
        #   For IDA 6.9 and newer using PyQt5
        # from PyQt5 import QtGui, QtWidgets, QtCore
        from PyQt5 import QtGui, QtWidgets
        from PyQt5.QtCore import Qt
    except ImportError:
        print 'Cannot import required Qt Modules'

# =====================  Utility functions  =====================


def populate_tree(treemodel, calls, filter_fname=None, filter_dllname=None, filter_addr_from=None, filter_return_addr=None):
    '''
    Helper for populating a tree model given a list of functions
    '''
    treemodel.removeRows(0, treemodel.rowCount())

    for (addr_from, addr_to) in calls:
        if filter_addr_from is not None:
            if not fnmatch.fnmatch(("%x" % addr_from).lower(), filter_addr_from):
                continue

        data = calls[(addr_from, addr_to)]
        for call in data:
            if filter_fname is not None:
                if not fnmatch.fnmatch(call.fun.lower(), filter_fname):
                    continue
            if filter_dllname is not None:
                if not fnmatch.fnmatch(call.mod.lower(), filter_dllname):
                    continue
            if filter_return_addr is not None:
                if not fnmatch.fnmatch(("%x" % call.ret_addr).lower(), filter_return_addr):
                    continue

            func_item = QtGui.QStandardItem(call.fun)
            font = QtGui.QFont()
            font.setBold(True)
            func_item.setFont(font)
            treemodel.appendRow([func_item, QtGui.QStandardItem(call.mod), QtGui.QStandardItem(
                "%x" % addr_from), QtGui.QStandardItem("%x" % call.ret_addr)])
            args = sorted(call.in_args + call.out_args)
            for arg in args:
                if arg.is_output_arg():
                    first = QtGui.QStandardItem("%s" % arg.get_arg_name())
                    second = QtGui.QStandardItem("%s" % (arg.__str__()))
                    first.setBackground(QtGui.QColor(255, 193, 37, 127))
                    second.setBackground(QtGui.QColor(255, 193, 37, 127))
                    func_item.appendRow([first, second])
                else:
                    first = QtGui.QStandardItem("%s" % arg.get_arg_name())
                    second = QtGui.QStandardItem("%s" % (arg.__str__()))
                    first.setBackground(QtGui.QColor(164, 211, 238, 127))
                    second.setBackground(QtGui.QColor(164, 211, 238, 127))
                    func_item.appendRow([first, second])
            if call.ret is not None and call.ret is not "":
                first = QtGui.QStandardItem("%s" % call.ret.get_arg_name())
                second = QtGui.QStandardItem("%s" % (call.ret.__str__()))
                first.setBackground(QtGui.QColor(240, 128, 128, 127))
                second.setBackground(QtGui.QColor(240, 128, 128, 127))
                func_item.appendRow([first, second])
                # func_item.appendRow(QtGui.QStandardItem("[RET] %s: %s" %
                # (call.ret.get_arg_name(),call.ret.__str__())))

            # Add to func_item, as childs (appendRow), each function parameter
            # (and so on, recursively).

        # Example of how to create children,etc.
        # treemodel.appendRow([QtGui.QStandardItem("AAA"),QtGui.QStandardItem("111")])
        # item = QtGui.QStandardItem("BBB")
        # treemodel.appendRow([item,QtGui.QStandardItem("222")])
        # item2 = QtGui.QStandardItem("CCC")
        # item.appendRow(item2)

# =====================  Context dialog to show functions in IDA view =====


class ShowFuncDialog(QtWidgets.QDialog):

    def __init__(self, parent, addrs):
        super(ShowFuncDialog, self).__init__(parent)
        # List of calls associated to the dialog
        self.addrs = addrs
        self.callback_fn = None
        self.setModal(True)
        self.setWindowTitle("Function")
        self.accepted.connect(self.success_callback)
        self.rejected.connect(self.success_callback)

        # Contents of the dialog.
        self.hbox = QtWidgets.QHBoxLayout(self)

        self.treeview = QtWidgets.QTreeView()
        self.hbox.addWidget(self.treeview)
        self.treemodel = QtGui.QStandardItemModel()
        self.treemodel.setHorizontalHeaderLabels(
            ["Function", "Dll", "Caller", "Return"])
        self.treeview.setModel(self.treemodel)

        # Populate the dialog, based on selected address
        addr = idc.ScreenEA()
        populate_tree(
            self.treemodel, self.addrs, filter_addr_from="%x" % addr)

    def register_success_callback(self, fn):
        self.callback_fn = fn

    def success_callback(self):
        if self.callback_fn is not None:
            self.callback_fn()

    def show(self):
        super(ShowFuncDialog, self).show()

# =====================  Dialog to show file loading status ===============


class LoadFuncsThread(threading.Thread):

    def __init__(self, func):
        threading.Thread.__init__(self)
        self.func = func

    def run(self):
        self.func()


class ShowLoadFuncDialog(QtWidgets.QDialog):

    def __init__(self, parent, file_name):
        super(ShowLoadFuncDialog, self).__init__(parent)
        # Attributes
        self.stopped = False
        self.file_name = file_name

        # Basic conf
        self.success_callback_fn = None
        self.setModal(True)
        self.vbox = QtWidgets.QVBoxLayout(self)
        self.setWindowTitle("Loading...")
        self.accepted.connect(self.success_callback)
        self.rejected.connect(self.reject_callback)

        # Contents: label
        self.func_lbl = QtWidgets.QLabel()
        self.func_lbl.setText("Loading functions, please, wait...")
        self.vbox.addWidget(self.func_lbl)

        # Contents: button
        self.btn_accept = QtWidgets.QPushButton('Import')
        width = self.btn_accept.fontMetrics().boundingRect(
            'Import').width() + 30
        self.btn_accept.setMaximumWidth(width)
        self.btn_accept.setEnabled(False)

        # Clicking the button generates an accept for this form
        self.btn_accept.clicked.connect(self.accept)
        self.vbox.addWidget(self.btn_accept)
        self.vbox.setAlignment(self.btn_accept, Qt.AlignHCenter)

    # Success callback for the dialog

    def register_success_callback(self, fn):
        self.success_callback_fn = fn

    def success_callback(self):
        if self.success_callback_fn is not None:
            self.success_callback_fn()

    def reject_callback(self):
        # When the dialog is closed at any moment
        self.stopped = True
        self.procs = None

    def show(self):
        super(ShowLoadFuncDialog, self).show()

    def showEvent(self, event):
        '''
        Overriden method.
        '''
        super(ShowLoadFuncDialog, self).showEvent(event)
        # Start loading functions when dialog is shown, in a separate thread
        self.load_thread = LoadFuncsThread(self.load_functions)
        self.load_thread.start()

    def load_functions(self):
        # Load the file with the functions, executed in a thread
        try:
            f_in = open(self.file_name, "rb")
            data = pickle.load(f_in)
            f_in.close()
            if not self.stopped:
                if type(data) is list:
                    self.procs = data
                else:
                    self.procs = data.procs
        except Exception:
            # If something goes wrong, report it, and do not load procs
            self.procs = None
            self.func_lbl.setText("Error loading file!")
            self.btn_accept.setText("Continue")
            traceback.print_exc()
        finally:
            # In all cases, enable button so that the user can exit cleanly
            self.btn_accept.setEnabled(True)

# =====================  Generic action handler for keyboard shortcut =====


class MyActionHandler(idaapi.action_handler_t):

    def __init__(self, fn):
        idaapi.action_handler_t.__init__(self)
        self.fn = fn

    def activate(self, ctx):
        self.fn(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# =====================  Hooks class for the context menu =====================


class Hooks(idaapi.UI_Hooks):

    def __init__(self, form):
        super(Hooks, self).__init__()
        self.is_closed = False
        self.addrs = None

    def set_addrs(self, addrs):
        self.addrs = addrs

    def populating_tform_popup(self, form, popup):
        # You can attach here.
        pass

    def finish_populating_tform_popup(self, form, popup):
        # Or here, after the popup is done being populated by its owner.

        # We will attach our action to the context menu
        # for the 'Functions window' widget.
        # The action will be be inserted in a submenu of
        # the context menu, named 'Others'.
        if not self.is_closed and idaapi.get_tform_type(form) == idaapi.BWN_DISASMS:
            addr = idc.ScreenEA()
            for addr_from, addr_to in self.addrs:
                if addr == addr_from:
                    idaapi.attach_action_to_popup(
                        form, popup, "pyrebox:show_funcs", "PyREBox/")
                    break

# =====================  Main plugin class =====================


class PyREBoxFunctionsFormClass(idaapi.PluginForm):

    def __init__(self):
        super(PyREBoxFunctionsFormClass, self).__init__()
        # Reference to the context menu hook
        self.hooks = None
        # Data organised by proc and call address
        self.addrs = {}
        # Whole raw parsed data
        self.procs = []

    def OnCreate(self, form):
        '''
        On create event, overriden
        '''
        # Update parent
        self.parent = self.FormToPyQtWidget(form)
        # Populate contents
        self.populate_form()
        # Initialize context menu hook
        self.hooks = Hooks(self)
        self.hooks.hook()

    def show_func_dialog(self, ctx=None):
        '''
        Show the individual function dialog when necessary, given the
        selected process.
        '''
        # Get process selected in combo
        pid = self.get_combo_pid()
        # Search for the process, and show dialog, passing the list of calls
        # for the selected process.
        if self.procs is not None:
            for proc in self.procs:
                if proc.pid == pid:
                    dialog = ShowFuncDialog(self.parent, self.addrs[proc])
                    dialog.show()
                    break

    def get_combo_pid(self):
        '''
        Get selected combo option
        '''
        text = self.combo_pids.currentText()
        if text != "":
            try:
                return int(text, 16)
            except Exception:
                print "Incorrect process selection!"
                return 0
        else:
            print "Incorrect process selection!"
            return 0

    def apply_functions(self, rename=False):
        '''
        Apply colors to the IDA view for the selected process, and update hook
        so that the context option is shown whenever we right click on an address
        with a call within the selected process
        '''
        self.current_selected_pid = self.get_combo_pid()
        for proc in self.procs:
            if proc.pid == self.current_selected_pid:
                for (addr_from, addr_to) in self.addrs[proc]:
                    idc.SetColor(addr_from, idc.CIC_ITEM, 0x8aa7ff)
                    if rename:
                        for call in self.addrs[proc][(addr_from, addr_to)]:
                            call_addr = idc.PrevHead(call.ret_addr)
                            mnemonic = idc.GetMnem(call_addr)
                            if mnemonic == "jmp" or mnemonic == "call":
                                addr_to_rename = idc.GetOperandValue(call_addr, 0)
                                if idaapi.isLoaded(addr_to_rename):
                                    idc.MakeName(addr_to_rename, call.fun)
                                    idc.MakeComm(call_addr, call.fun)
                # Update hooks
                self.hooks.set_addrs(self.addrs[proc])

    def file_loaded(self):
        '''
        Event called when the ShowLoadFuncDialog triggers and accept (success callback)
        '''
        # Get the data we just loaded and update procs
        self.procs = self.load_funcs_dialog.procs

        if self.procs is not None:

            # Generate the addrs dictionary (addr_from,addr_to) ->
            # list(data,data,data)
            for proc in self.procs:
                if proc not in self.addrs:
                    self.addrs[proc] = {}
                for vad in proc.vads:
                    for addr_from, addr_to, data in vad.calls:
                        if (addr_from, addr_to) not in self.addrs[proc]:
                            self.addrs[proc][(addr_from, addr_to)] = []
                        self.addrs[proc][(addr_from, addr_to)].append(data)
                for addr_from, addr_to, data in proc.other_calls:
                    if (addr_from, addr_to) not in self.addrs[proc]:
                        self.addrs[proc][(addr_from, addr_to)] = []
                    self.addrs[proc][(addr_from, addr_to)].append(data)

            # Update combo with the pids for the processes
            proc_pids = []
            for proc in self.procs:
                proc_pids.append(proc.__str__())
            self.combo_pids.addItems(proc_pids)

            # Populate the function tree for the currently selected process
            # (default process)
            pid = self.get_combo_pid()
            if self.procs is not None:
                for proc in self.procs:
                    if proc.pid == pid:
                        populate_tree(self.treemodel, self.addrs[proc])
                        break

    def load_file(self):
        '''
        Load file button event. Opens the file load dialog
        '''
        self.load_funcs_dialog = ShowLoadFuncDialog(
            self.parent, self.selected_file[0])
        # Register the success callback for the function load dialog
        self.load_funcs_dialog.register_success_callback(self.file_loaded)
        self.load_funcs_dialog.show()

    def show_file_dialog(self):
        '''
        Show open file dialog for selecting the file, and update the text box.
        '''
        fname = QtWidgets.QFileDialog.getOpenFileName(self.parent, 'Open file',
                                                      'C:\\')
        self.selected_file = fname
        self.choose_file_lineedit.setText(fname[0])
        # Enable or disable the button based on the validity of the file name
        if len(fname[0]) > 0 and os.path.isfile(fname[0]):
            self.btn_loadfile.setEnabled(True)
        else:
            self.btn_loadfile.setEnabled(False)

    def combo_pids_changed(self, text):
        '''
        Combobox selection changed event
        '''
        # Populate the function tree for the currently selected process
        pid = self.get_combo_pid()
        if self.procs is not None:
            for proc in self.procs:
                if proc.pid == pid:
                    populate_tree(self.treemodel, self.addrs[proc])
                    break

    def filter_edited(self):
        filter_fname = None if self.filter_fname_lineedit.text().strip(
        ) == "" else "*%s*" % self.filter_fname_lineedit.text().strip().lower()
        filter_dllname = None if self.filter_dll_lineedit.text().strip(
        ) == "" else "*%s*" % self.filter_dll_lineedit.text().strip().lower()
        filter_addr_from = None if self.filter_caller_lineedit.text().strip(
        ) == "" else "*%s*" % self.filter_caller_lineedit.text().strip().lower()
        filter_return_addr = None if self.filter_return_lineedit.text().strip(
        ) == "" else "*%s*" % self.filter_return_lineedit.text().strip().lower()
        # Populate the function tree for the currently selected process
        # (default process)
        pid = self.get_combo_pid()
        if self.procs is not None:
            for proc in self.procs:
                if proc.pid == pid:
                    populate_tree(self.treemodel, self.addrs[proc],
                                  filter_fname=filter_fname,
                                  filter_dllname=filter_dllname,
                                  filter_addr_from=filter_addr_from,
                                  filter_return_addr=filter_return_addr)
                    break

    def populate_form(self):
        '''
        Populate form contents
        '''
        # Main layout
        # ---------------------
        main_layout = QtWidgets.QVBoxLayout()
        self.parent.setLayout(main_layout)

        # Choose file group box
        # ---------------------
        choose_file_groupbox = QtWidgets.QGroupBox(
            "Choose file to load (interproc or apitracer binary file)")
        choose_file_groupbox_layout = QtWidgets.QHBoxLayout()
        choose_file_groupbox.setLayout(choose_file_groupbox_layout)
        main_layout.addWidget(choose_file_groupbox)

        # Line edit
        self.choose_file_lineedit = QtWidgets.QLineEdit("")
        self.choose_file_lineedit.setReadOnly(True)

        # Select button
        btn_selectfile = QtWidgets.QPushButton('Select', self.parent)
        width = btn_selectfile.fontMetrics().boundingRect(
            'Select').width() + 30
        btn_selectfile.setMaximumWidth(width)
        btn_selectfile.clicked.connect(self.show_file_dialog)

        # Load functions button
        self.btn_loadfile = QtWidgets.QPushButton(
            'Load functions', self.parent)
        width = self.btn_loadfile.fontMetrics().boundingRect(
            'Load functions').width() + 30
        self.btn_loadfile.setMaximumWidth(width)
        self.btn_loadfile.setEnabled(False)
        self.btn_loadfile.clicked.connect(self.load_file)

        choose_file_groupbox_layout.addWidget(self.choose_file_lineedit)
        choose_file_groupbox_layout.addWidget(btn_selectfile)
        choose_file_groupbox_layout.addWidget(self.btn_loadfile)

        # Choose PID groupbox
        # ---------------------

        choose_pid_groupbox = QtWidgets.QGroupBox("Choose PID to visualize")
        choose_pid_groupbox_layout = QtWidgets.QHBoxLayout()
        choose_pid_groupbox.setLayout(choose_pid_groupbox_layout)
        main_layout.addWidget(choose_pid_groupbox)

        # Combobox
        self.combo_pids = QtWidgets.QComboBox()
        self.combo_pids.setEditable(False)
        self.combo_pids.currentIndexChanged[
            'QString'].connect(self.combo_pids_changed)
        choose_pid_groupbox_layout.addWidget(self.combo_pids)

        # Apply button
        btn_apply = QtWidgets.QPushButton('Apply', self.parent)
        width = btn_apply.fontMetrics().boundingRect('Apply').width() + 30
        btn_apply.setMaximumWidth(width)
        btn_apply.clicked.connect(self.apply_functions)
        choose_pid_groupbox_layout.addWidget(btn_apply)

        # Apply and rename button
        btn_apply_rename = QtWidgets.QPushButton(
            'Apply and rename', self.parent)
        width = btn_apply.fontMetrics().boundingRect(
            'Apply and rename').width() + 30
        btn_apply_rename.setMaximumWidth(width)
        btn_apply_rename.clicked.connect(
            functools.partial(self.apply_functions, rename=True))
        choose_pid_groupbox_layout.addWidget(btn_apply_rename)

        # Filters groupbox
        # ---------------------

        filter_groupbox = QtWidgets.QGroupBox("Filter functions")
        filter_groupbox_layout = QtWidgets.QGridLayout()
        filter_groupbox_layout.setSpacing(10)
        filter_groupbox.setLayout(filter_groupbox_layout)
        main_layout.addWidget(filter_groupbox)

        # Filter 1 - Function name

        filter1_label = QtWidgets.QLabel()
        filter1_label.setText("Function name")
        filter_groupbox_layout.addWidget(filter1_label, 1, 0)

        self.filter_fname_lineedit = QtWidgets.QLineEdit("")
        self.filter_fname_lineedit.setReadOnly(False)
        filter_groupbox_layout.addWidget(self.filter_fname_lineedit, 1, 1)
        self.filter_fname_lineedit.textEdited.connect(self.filter_edited)

        # Filter 2 - Dll name

        filter2_label = QtWidgets.QLabel()
        filter2_label.setText("DLL name")
        filter_groupbox_layout.addWidget(filter2_label, 2, 0)

        self.filter_dll_lineedit = QtWidgets.QLineEdit("")
        self.filter_dll_lineedit.setReadOnly(False)
        filter_groupbox_layout.addWidget(self.filter_dll_lineedit, 2, 1)
        self.filter_dll_lineedit.textEdited.connect(self.filter_edited)

        # Filter 3 - Caller

        filter3_label = QtWidgets.QLabel()
        filter3_label.setText("Caller")
        filter_groupbox_layout.addWidget(filter3_label, 3, 0)

        self.filter_caller_lineedit = QtWidgets.QLineEdit("")
        self.filter_caller_lineedit.setReadOnly(False)
        filter_groupbox_layout.addWidget(self.filter_caller_lineedit, 3, 1)
        self.filter_caller_lineedit.textEdited.connect(self.filter_edited)

        # Filter 4 - Return

        filter4_label = QtWidgets.QLabel()
        filter4_label.setText("Return")
        filter_groupbox_layout.addWidget(filter4_label, 4, 0)

        self.filter_return_lineedit = QtWidgets.QLineEdit("")
        self.filter_return_lineedit.setReadOnly(False)
        filter_groupbox_layout.addWidget(self.filter_return_lineedit, 4, 1)
        self.filter_return_lineedit.textEdited.connect(self.filter_edited)

        # QTreeView
        # ----------------------

        self.treeview = QtWidgets.QTreeView()
        main_layout.addWidget(self.treeview)
        self.treemodel = QtGui.QStandardItemModel()
        self.treemodel.setHorizontalHeaderLabels(
            ["Function", "Dll", "Caller", "Return"])
        self.treeview.setModel(self.treemodel)

        # Keyboard shortcut, and action handler
        # -------------------------------------

        handler = MyActionHandler(self.show_func_dialog)
        self.menu_action = idaapi.action_desc_t('pyrebox:show_funcs',
                                                'Show function arguments',
                                                handler,
                                                'Ctrl+Alt+S',
                                                'Show function arguments',
                                                0)
        idaapi.register_action(self.menu_action)

        # Regular menu entry
        # -------------------------------------

        # The relative path of where to add the action
        idaapi.attach_action_to_menu('Edit/Other/Show function arguments...',
                                     'pyrebox:show_funcs',
                                     # The action ID (see above)
                                     idaapi.SETMENU_APP)
        # We want to append the action after the 'Manual instruction...'

    def OnClose(self, form):
        '''
        OnClose event, overriden. Just unhook stuff.
        '''
        try:
            idaapi.unregister_action('pyrebox:show_funcs')
            idaapi.detach_action_from_menu(
                'Edit/PyREBox/Show function arguments...', 'pyrebox:show_funcs')
            self.hooks.is_closed = True
            pass
        except Exception:
            traceback.print_exc()


# Start the plugin and name the tab
plg = PyREBoxFunctionsFormClass()
plg.Show("PyREBox - Functions")

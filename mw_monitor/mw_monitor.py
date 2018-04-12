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

#!/usr/bin/python
from __future__ import print_function
import ConfigParser
import os
import shutil
import functools
import tempfile
import zipfile
import json
import ntpath
import tarfile

from api import CallbackManager
from mw_monitor_logging import serialize_calls
from mw_monitor_logging import serialize_interproc
from mw_monitor_logging import interproc_basic_stats
from mw_monitor_logging import log_coverage

requirements = ["plugins.guest_agent"]

def new_process(pid, pgd, name):
    '''
    Monitor process creation in order to start tracing the first process.
    '''
    from DeviareDbParser import DbConnector
    from mw_monitor_classes import mwmon
    from mw_monitor_classes import mw_monitor_start_monitoring_process

    main_proc = mwmon.data.procs[0]
    if main_proc.get_proc_name() is not None and (main_proc.get_proc_name() in name or name in main_proc.get_proc_name()):
        mwmon.printer("Starting monitoring process %s" % name)
        main_proc.set_pgd(pgd)
        main_proc.set_pid(pid)
        if mwmon.api_tracer and not mwmon.api_tracer_light_mode:
            mwmon.printer("Loading API tracer database...")
            # Initialize API doc database. We need to initialize it in this thread (callback),
            # because sqlite limits db access to 1 thread, and the rest of callbacks should be
            # running on this same thread.
            mwmon.db = DbConnector(mwmon.api_database_path)

        mw_monitor_start_monitoring_process(main_proc, insert_proc=False)

        mwmon.cm.rm_callback("vmi_new_proc")

# Monitor process removal 
def remove_process(pid, pgd, name):
    from mw_monitor_classes import mwmon
    from api import unload_module

    for proc in mwmon.data.procs:
        if proc.get_pid() == pid and proc.has_exited() is False:
            proc.set_exited()
            mwmon.printer("Process %s (%x) exited" % (name, pid))

    # If all the processes have exited, unload mwmon
    # if all([proc.has_exited() for proc in mwmon.data.procs]):
        #unload_module(mwmon.cm.get_module_handle())

def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    from mw_monitor_logging import log_calls
    from mw_monitor_classes import mwmon
    # import tarfile

    mwmon.printer("Cleaning module")
    mwmon.cm.clean()
    mwmon.printer("Cleaned module")

    out_bundle = tarfile.open(mwmon.output_bundle_name,"w:gz")
    if os.path.isfile('mw_monitor_run.json'):
       out_bundle.add('mw_monitor_run.json')

    if mwmon.api_tracer and mwmon.api_tracer_text_log:
        mwmon.printer("Writing text call log")
        log_calls()
        if os.path.isfile(mwmon.api_tracer_text_log_name):
            out_bundle.add(mwmon.api_tracer_text_log_name)

    if mwmon.api_tracer and mwmon.api_tracer_bin_log:
        mwmon.printer("Writing binary call log")
        serialize_calls()
        if os.path.isfile(mwmon.api_tracer_bin_log_name):
            out_bundle.add(mwmon.api_tracer_bin_log_name)

    if mwmon.interproc and mwmon.interproc_bin_log:
        mwmon.printer("Writing interproc bin log")
        serialize_interproc()
        if os.path.isfile(mwmon.interproc_bin_log_name):
            out_bundle.add(mwmon.interproc_bin_log_name)

    if mwmon.interproc and mwmon.interproc_basic_stats:
        mwmon.printer("Writing interproc text log")
        interproc_basic_stats()
        if os.path.isfile(mwmon.interproc_basic_stats_name):
            out_bundle.add(mwmon.interproc_basic_stats_name)

    if mwmon.interproc_text_log_handle is not None:
        mwmon.interproc_text_log_handle.close()
        mwmon.interproc_text_log_handle = None
        if os.path.isfile(mwmon.interproc_text_log_name):
            out_bundle.add(mwmon.interproc_text_log_name)

    if mwmon.coverage:
        mwmon.printer("Processing coverage")
        log_coverage()
        if os.path.isfile(mwmon.coverage_log_name):
            out_bundle.add(mwmon.coverage_log_name)
        if os.path.isfile(mwmon.coverage_text_name):
            out_bundle.add(mwmon.coverage_text_name)

    if mwmon.dumper:
        mwmon.printer("Adding dumped memory")
        # Add the dumped stuff.
        if os.path.isdir(mwmon.dumper_path):
            mwmon.printer(mwmon.dumper_path)
            out_bundle.add(mwmon.dumper_path)

    # Remove the temporary extracted files
    if os.path.isdir(mwmon.extracted_files_path):
        shutil.rmtree(mwmon.extracted_files_path)

    out_bundle.close()

    mwmon.printer("Module unloaded")

def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from mw_monitor_classes import Process
    from mw_monitor_classes import mwmon
    import dumper
    import api
    from ipython_shell import add_command
    from plugins.guest_agent import guest_agent

    # Update printer
    mwmon.printer = printer
    # Read configuration
    mwmon.printer("Reading mw_monitor configuration...")
    # Config parser for main static configuration file
    config = ConfigParser.RawConfigParser()
    config.read('mw_monitor.conf')

    # Read run configuration from json file
    f = open("mw_monitor_run.json","r")
    config_run = json.load(f)
    f.close()

    # GENERAL CONFIGURATION
    if "files_path" not in config_run["general"] or \
       "main_executable" not in config_run["general"] or \
       "files_bundle" not in config_run["general"]:
        raise ValueError("File to run not properly specified")

    mwmon.output_bundle_name = config.get('general', 'output_bundle')
    mwmon.files_path = config_run['general']['files_path']
    mwmon.main_executable = config_run['general']['main_executable']
    mwmon.files_bundle = config_run['general']['files_bundle']
    mwmon.api_database_path = config.get('general', 'api_database')

    # Set up process copy and execution
    mwmon.printer("Copying host file to guest, using agent...")

    #Extract files in a temporary directory
    extracted_files_path = tempfile.mkdtemp()
    mwmon.extracted_files_path = extracted_files_path
    zip_ref = zipfile.ZipFile(mwmon.files_bundle, 'r')
    zip_ref.extractall(extracted_files_path)
    zip_ref.close()
    onlyfiles = [f for f in os.listdir(extracted_files_path) if os.path.isfile(os.path.join(extracted_files_path, f))]

    #Copy the files to the guest
    for f in onlyfiles:
        guest_agent.copy_file(os.path.join(extracted_files_path,f),os.path.join(mwmon.files_path,f))

    ex_path = str(ntpath.join(mwmon.files_path,mwmon.main_executable))
    # Instruct file execution
    guest_agent.execute_file(ex_path)

    # Stop agent
    # guest_agent.stop_agent()

    # MODULE CONFIGURATION
    mwmon.api_tracer = config_run['modules']['api_tracer']
    mwmon.interproc = config_run['modules']['interproc']
    mwmon.coverage = config_run['modules']['coverage']
    mwmon.dumper = config_run['modules']['dumper']

    # API TRACER CONFIGURATION
    if mwmon.api_tracer and "api_tracer" in config_run:
        # Static config
        mwmon.api_tracer_text_log_name = config.get(
            'api_tracer', 'text_log_name')
        mwmon.api_tracer_bin_log_name = config.get(
            'api_tracer', 'bin_log_name')

        # Run config
        mwmon.api_tracer_light_mode = config_run['api_tracer']['light_mode']
        mwmon.api_tracer_text_log = config_run['api_tracer']['text_log']
        mwmon.api_tracer_bin_log = config_run['api_tracer']['bin_log']

        if "include_apis" in config_run["api_tracer"]:
            mwmon.include_apis = []
            mwmon.include_apis_addrs = []
            for api_call in config_run["api_tracer"]["include_apis"]:
                try:
                    mod, fun = api_call.split("!")
                    mwmon.include_apis.append((mod.lower(), fun.lower()))
                except Exception:
                    # Just pass over the malformed api names
                    pass
        else:
            mwmon.include_apis = None

        if "exclude_apis" in config_run["api_tracer"]:
            mwmon.exclude_apis = []
            mwmon.exclude_apis_addrs = []
            for api_call in config_run["api_tracer"]["exclude_apis"]:
                try:
                    mod, fun = api_call.split("!")
                    mwmon.exclude_apis.append((mod.lower(), fun.lower()))
                except Exception:
                    # Just pass over the malformed api names
                    pass
        else:
            mwmon.excludeapis = None

        if "procs" in config_run["api_tracer"]:
            mwmon.api_tracer_procs = config_run["api_tracer"]["procs"]
        else:
            mwmon.api_tracer_procs = None

        if "exclude_modules" in config_run["api_tracer"]:
            mwmon.exclude_modules_addrs = []
            mwmon.exclude_modules = [s.lower() for s in config_run["api_tracer"]["exclude_modules"]]
        else:
            mwmon.exclude_modules = None

        if "exclude_origin_modules" in config_run["api_tracer"]:
            mwmon.exclude_origin_modules_addrs = []
            mwmon.exclude_origin_modules = [s.lower() for s in config_run["api_tracer"]["exclude_origin_modules"]]
        else:
            mwmon.exclude_origin_modules = None
            mwmon.exclude_origin_modules_addrs = None


    # interproc configuration 
    if mwmon.interproc:
        # Static config
        mwmon.interproc_bin_log_name = config.get('interproc', 'bin_log_name')
        mwmon.interproc_text_log_name = config.get(
            'interproc', 'text_log_name')
        mwmon.interproc_basic_stats_name = config.get(
            'interproc', 'basic_stats_name')
        # Run config
        mwmon.interproc_bin_log = config_run['interproc']['bin_log']
        mwmon.interproc_text_log = config_run['interproc']['text_log']
        mwmon.interproc_basic_stats = config_run['interproc']['basic_stats']
        if mwmon.interproc_text_log:
            mwmon.interproc_text_log_handle = open(
                mwmon.interproc_text_log_name, "w")

    if mwmon.coverage:
        # Static config
        mwmon.coverage_log_name = config.get('coverage', 'cov_log_name')
        mwmon.coverage_text_name = config.get('coverage', 'cov_text_name')
        # Run config
        if "procs" in config_run["coverage"]:
            mwmon.coverage_procs = config_run["coverage"]["procs"]
        else:
            mwmon.coverage_procs = None

    # Static config
    mwmon.dumper_path = config.get('dumper', 'path')

    # DUMPER CONFIGURATION
    if mwmon.dumper:
        if os.path.isdir(mwmon.dumper_path):
            shutil.rmtree(mwmon.dumper_path)
        os.makedirs(mwmon.dumper_path)

        # Run config
        mwmon.dumper_onexit = config_run['dumper']['dump_on_exit']
        # Possible formats for dump_at:
        # 0x00400000
        # user32.dll!CharNextW
        # user32.dll!CharNextW!0x00400000
        if "dump_at" in config_run["dumper"]:
            mwmon.dumper_dumpat = config_run['dumper']['dump_at']

    mwmon.printer("Initializing callbacks")
    mwmon.cm = CallbackManager(module_hdl)

    # Initialize first process
    proc_name = mwmon.main_executable
    mwmon.data.procs = [Process(proc_name)]

    procs = api.get_process_list()
    match_procs = []
    for proc in procs:
        name = proc["name"]
        pid = proc["pid"]
        pgd = proc["pgd"]
        if proc_name is not None and (proc_name in name or name in proc_name):
            match_procs.append((pid, pgd, name))

    if len(match_procs) == 0:
        mwmon.printer(
            "No process matching that process name, deferring process detection")
        mwmon.printer("Initializing process creation callback")
        # Monitor creation of new processes, to start tracing the first one.
        mwmon.cm.add_callback(
            CallbackManager.CREATEPROC_CB, new_process, name="vmi_new_proc")
    elif len(match_procs) == 1:
        mwmon.printer(
            "Process found with the name specified, monitoring process...")
        new_process(match_procs[0][0], match_procs[0][1], match_procs[0][2])
    else:
        mwmon.printer(
            "Too many procs matching that name, please narrow down!!")

    if mwmon.dumper:
        mwmon.printer("Adding dumper commands")
        # Create and activate new command (dump_mwmon)
        add_command("dump_mwmon", dumper.dump_command)

    # Add a callback on process remove, to know when 
    # we dont have any monitored process left.
    mwmon.cm.add_callback(
        CallbackManager.REMOVEPROC_CB, remove_process, name="mwmon_vmi_remove_proc")


    mwmon.printer("Initialized callbacks")


if __name__ == "__main__":
    print("Loading python module %s" % (__file__))

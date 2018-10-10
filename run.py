# -------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
#                                PyREBox run.py 
#                                ==============
#
#   USAGE:  Configure the following environment variables.
#
#           VM_IMAGE = 
#           VM_SNAPSHOT = 
#           PYREBOX_PATH = 
#           RAM = 
#           TIMEOUT = 
#           CONFIG_PATH = 
#           AUTORUN_CONF_PATH = 
#
#   or provide them as parameters to start_pyrebox
#
#
#           (Optionally, depending on which modules are enabled on
#           the pyrebox configuration file (CONFIG_PATH))
#       
#           GENERIC_UNPACKER_CONF_PATH =
#
# -------------------------------------------------------------------------------


from threading import Thread
import argparse
import subprocess
import os
import signal
import fcntl
import time
import sys

# Maximum time we wait for the unload 
# process to finish before we kill the
# process
MAX_UNLOAD_TIME = 60

VM_IMAGE = os.environ.get("VM_IMAGE", None)
VM_SNAPSHOT = os.environ.get("VM_SNAPSHOT", None)
PYREBOX_PATH = os.environ.get("PYREBOX_PATH", None)
RAM = os.environ.get("RAM", None)
TIMEOUT = os.environ.get("TIMEOUT", 60 * 5)
CONFIG_PATH = os.environ.get("CONFIG_PATH", "pyrebox.conf")
AUTORUN_CONF_PATH = os.environ.get("AUTORUN_CONF_PATH", "autorun.conf")

# Process handle
p = None

def log(s, std_log_file = None):
    if std_log_file:
        with open(std_log_file, "a") as f:
            f.write(s + "\n")
    else:
        print(s)

def signal_handler(sig, frame):
    global p
    if p:
        print("Killing PyREBox process...")
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        p = None
    sys.exit(0)

def start_pyrebox(vm_image = VM_IMAGE,
                vm_snapshot = VM_SNAPSHOT,
                pyrebox_path = PYREBOX_PATH,
                ram = RAM,
                timeout_analysis = TIMEOUT,
                config = CONFIG_PATH,
                autorun_config = AUTORUN_CONF_PATH,
                std_log_file = None):
    global p

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if vm_image is None or not os.path.isfile(vm_image):
            raise ValueError("The specified path for the VM image is incorrect.")
        if vm_snapshot is None or (not isinstance(vm_snapshot, str) and not isinstance(vm_snapshot, unicode)):
            raise ValueError("The specified snapshot is not a valid string")
        if ram is None:
            raise ValueError("The specified value for RAM is not valid")
        if pyrebox_path is None or (not os.path.isfile(pyrebox_path) and not os.path.islink(pyrebox_path)):
            raise ValueError("The specified pyrebox path is not a valid file")
        if timeout_analysis is None or not isinstance(timeout_analysis, int):
            raise ValueError("The specified timeout is not a valid int value")
        if config is None or not os.path.isfile(config):
            raise ValueError("The specified path for the config file is not valid")
        if autorun_config is None or (not isinstance(autorun_config, str) and not isinstance(autorun_config, unicode)):
            raise ValueError("The specified path for the autorun config file is not valid")

        # Autorun module handle (so that we can unload it)
        module_handle = None

        try:
            #Insert this as commands
            pyrebox_command = "{pyrebox_path} -monitor stdio -m {ram} -usb -usbdevice tablet " + \
                              "-drive file={vm_img},index=0,media=disk,format=qcow2,cache=unsafe " + \
                              "-vnc 127.0.0.1:0 -loadvm {snapshot} -conf {config_path} -net none"

            pyrebox_command = pyrebox_command.format(vm_img=vm_image,
                                                     snapshot=vm_snapshot,
                                                     pyrebox_path=pyrebox_path,
                                                     ram = ram,
                                                     config_path = config)

            # Make sure we set environment variable
            pyrebox_env = os.environ.copy()
            pyrebox_env["AUTORUN_CONF_PATH"] = autorun_config
            current_ld_library_path = os.getenv('LD_LIBRARY_PATH', '')
            p = subprocess.Popen(args=pyrebox_command,
                                 env=pyrebox_env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=True,
                                 env={"LD_LIBRARY_PATH": "sleuthkit/tsk/.libs:%s" % (current_ld_library_path)}
                                 # Open the process on a new session
                                 preexec_fn=os.setsid)

            log("Started PyREBox...", std_log_file)
            fl = fcntl.fcntl(p.stdout, fcntl.F_GETFL)
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            fl = fcntl.fcntl(p.stderr, fcntl.F_GETFL)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        except Exception as e:
            msg = "Error loading PyREBox: %s" % str(e)
            log(msg, std_log_file)
            if p:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                p = None
            raise Exception(msg)

        start_time = time.time()
        while True:
            #Wait analysis timeout 
            if (time.time() - start_time) > timeout_analysis:
                msg = "PyREBox did not finish in %d seconds" % timeout_analysis
                log(msg, std_log_file)

                if module_handle is not None:
                    # Unload the mwmon module
                    p.stdin.write("unload_module %d\n" % module_handle)
                else:
                    log("Cannot unload modules, because module handle was not recorded", std_log_file)

                # Set a 60 second timeout for unload to happen
                start_time = time.time()
                timeout_unload = MAX_UNLOAD_TIME 
                while True:
                    if (time.time() - start_time) > timeout_unload:
                        msg = "Module unload did not happen in time"
                        log(msg, std_log_file)
                        if p:
                            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                            p = None
                        raise Exception(msg) 

                    time.sleep(0.1)

                    try:
                        s = p.stderr.read()
                        if len(s.strip()) > 0:
                            log(s, std_log_file)
                    except Exception as e:
                        pass

                    try:
                        s = p.stdout.read()
                        if len(s.strip()) > 0:
                            log(s, std_log_file)

                        if "[autorun.autorun] All modules unloaded" in s:
                            break
                    except Exception as e:
                        continue

                # Exit from first loop if we forced analysis stop
                break

            time.sleep(0.1)

            try:    
                s = p.stderr.read()
                if len(s.strip()) > 0:
                    log(s, std_log_file)
            except Exception as e:
                pass

            try:
                s = p.stdout.read()
                if len(s.strip()) > 0:
                    log(s, std_log_file)
                if "[autorun.autorun] All modules unloaded" in s:
                    break
                if "Module loaded:" in s:
                    import re
                    m = re.search(r"Module\sloaded:\s([0-9]+)", s)
                    if m:
                        module_handle = int(m.group(1))
            except Exception as e:
                continue

        if p:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            p = None

        return True
    except Exception as e:
        log("Exception occurred while running PyREBox: %s" % str(e), std_log_file)
        if p:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            p = None
        return False

if __name__ == "__main__":
    #Parse arguments
    parser = argparse.ArgumentParser(description='Start PyREBox')
    parser.add_argument("--image", help="Path to VM image")
    parser.add_argument("--snapshot", help="Snapshot to load")
    parser.add_argument("--path", help="PyREBox path")
    parser.add_argument("--ram", help="RAM memory to load the image (in Mb)")
    parser.add_argument("--timeout", help="Analysis timeout, in seconds")
    parser.add_argument("--config", help="Path to pyrebox configuration file")
    parser.add_argument("--autorun_config", help="Path to autorun configuration file")
    args = parser.parse_args()

    start_pyrebox(vm_image = args.image if args.image else VM_IMAGE,
                vm_snapshot = args.snapshot if args.snapshot else VM_SNAPSHOT,
                pyrebox_path = args.path if args.path else PYREBOX_PATH, 
                ram = args.ram if args.ram else RAM,
                timeout_analysis = int(args.timeout) if args.timeout else TIMEOUT,
                config = args.config if args.config else CONFIG_PATH,
                autorun_config = args.autorun_config if args.autorun_config else AUTORUN_CONF_PATH,
                std_log_file = "pyrebox_run.log")

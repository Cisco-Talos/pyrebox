import SocketServer
import threading
import struct
import string

import api
from utils import find_procs


# Printer
pyrebox_print = None

# RAP server
rs = None


class BaseRapHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        while True:
            try:
                self.handle_packet()
            except EOFError:
                pyrebox_print("Client disconnected")
                break
            except Exception as e:
                pyrebox_print("Protocol error: {}".format(e))
                break

    def handle_packet(self):
        buf = self._request_read(1)

        if len(buf) == 0:
            raise EOFError

        packet_type = ord(buf)

        if packet_type == RapServer.RAP_OPEN:
            buf = self._request_read(2)
            (flags, size) = struct.unpack(">BB", buf)
            name = self._request_read(size)
            fd = self.rap_open(name, flags)
            buf = struct.pack(">BI", RapServer.RAP_OPEN|RapServer.RAP_REPLY, fd)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_READ:
            buf = self._request_read(4)
            (size,) = struct.unpack(">I", buf)
            ret = self.rap_read(size)
            buf = struct.pack(">BI", RapServer.RAP_READ|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        elif packet_type == RapServer.RAP_WRITE:
            buf = self._request_read(4)
            (size,) = struct.unpack(">I", buf)
            buf = self._request_read(size)
            ret = self.rap_write(buf)
            buf = struct.pack(">BI", RapServer.RAP_WRITE|RapServer.RAP_REPLY, ret)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_SEEK:
            buf = self._request_read(9)
            (whence, offset) = struct.unpack(">BQ", buf)
            ret = self.rap_seek(offset, whence)
            buf = struct.pack(">BQ", RapServer.RAP_SEEK|RapServer.RAP_REPLY, ret)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_CLOSE:
            buf = self._request_read(4)
            (fd,) = struct.unpack(">I", buf)
            self.rap_close(fd)
            buf = struct.pack(">B", RapServer.RAP_CLOSE|RapServer.RAP_REPLY)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_SYSTEM:
            buf = self._request_read(4)
            (size,) = struct.unpack(">I", buf)
            buf = self._request_read(size)
            ret = self.rap_system(buf)
            buf = struct.pack(">BI", RapServer.RAP_SYSTEM|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        elif packet_type == RapServer.RAP_CMD:
            buf = self._request_read(4)
            (size,) = struct.unpack(">I", buf)
            buf = self._request_read(size)
            ret = self.rap_cmd(buf)
            buf = struct.pack(">BI", RapServer.RAP_CMD|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        else:
            raise Exception("unknown RAP packet type")

    def rap_open(self, name, flags):
        raise NotImplementedError

    def rap_read(self, size):
        raise NotImplementedError

    def rap_write(self, data):
        raise NotImplementedError

    def rap_seek(self, offset, whence):
        raise NotImplementedError

    def rap_close(self, fd):
        raise NotImplementedError

    def rap_system(self, cmd):
        raise NotImplementedError

    def rap_cmd(self, cmd):
        raise NotImplementedError

    def _request_read(self, sz, recvsz=1024):
        buf = ""

        while len(buf) < sz:
            if recvsz > sz - len(buf):
                recvsz = sz - len(buf)

            chunk = self.request.recv(recvsz)
            if len(chunk) == 0:
                break
            buf += chunk

        return buf


class DefaultRapHandler(BaseRapHandler):
    def __init__(self, *args, **kwargs):
        self.pid = 0
        self.pgd = 0
        self.pname = ""
        self.base = 0
        self.size = 0
        self.curseek = 0

        BaseRapHandler.__init__(self, *args, **kwargs)

    def rap_open(self, name, flags):
        for proc in api.get_process_list():
            if (name.isdigit() and int(name) == proc["pid"]) or (name in proc["name"]):
                self.pid = proc["pid"]
                self.pgd = proc["pgd"]
                self.pname = proc["name"]
                break
        else:
            raise Exception("Process not found: {}".format(name))

        module_list = api.get_module_list(self.pgd)
        for m in module_list:
            if m["name"] != self.pname:
                continue
            self.base = m["base"]
            self.size = m["size"]

        pyrebox_print("Selecting name={} pid={} base={:#x} size={}".format(
            self.pname, self.pid, self.base, self.size))

        return 0

    def rap_read(self, size):
        try:
            data = api.r_va(self.pgd, self.curseek, size)
        except Exception:
            pyrebox_print("Cannot read memory at {:#x}".format(self.curseek))
            data = ""

        return data

    def rap_write(self, data):
        try:
            api.w_va(self.pgd, self.curseek, data, len(data))
            size = len(data)
        except Exception:
            pyrebox_print("Cannot write memory at {:#x}".format(self.curseek))
            size = 0

        return size

    def rap_seek(self, offset, whence):
        if whence == RapServer.RAP_SEEK_SET:
            self.curseek = offset
        elif whence == RapServer.RAP_SEEK_CUR:
            self.curseek = self.curseek + offset
        elif whence == RapServer.RAP_SEEK_END:
            self.curseek = ((1<<64) - 1) - offset

        return self.curseek

    def rap_close(self, fd):
        self.pid = 0
        self.pgd = 0
        self.pname = ""
        self.base = 0
        self.size = 0
        self.curseek = 0

    def rap_system(self, cmd):
        pyrebox_print("RAP_SYSTEM not implemented")
        return ""

    def rap_cmd(self, cmd):
        cmd = cmd.strip(string.whitespace + "\x00")
        if len(cmd) == 0:
            pyrebox_print("RAP_CMD: malformed command")

        argv = cmd.split(" ")
        for element in dir(self):
            if element == "_cmd_{}".format(argv[0]):
                return getattr(self, element)(argv[1:])

        pyrebox_print("RAP_CMD: cmd '{}' not implemented".format(argv[0]))
        return ""

    def _cmd_lm(self, args):
        ret = ""

        try:
            for m in sorted(api.get_module_list(self.pgd), key=lambda k: k['base']):
                ret += "name={} base={:#x} size={:#x}\n".format(m["name"], m["base"], m["size"])
        except Exception as e:
            return "error: {}\n".format(e)

        return ret


class RapServer():
    # Packet types
    RAP_OPEN   = 1
    RAP_READ   = 2
    RAP_WRITE  = 3
    RAP_SEEK   = 4
    RAP_CLOSE  = 5
    RAP_SYSTEM = 6
    RAP_CMD    = 7
    RAP_REPLY  = 0x80

    # Seek whence
    RAP_SEEK_SET = 0
    RAP_SEEK_CUR = 1
    RAP_SEEK_END = 2


    def __init__(self, host, port, handler_class=DefaultRapHandler):
        self.host = host
        self.port = port
        self.server = SocketServer.TCPServer((host, port), handler_class)

    def serve(self):
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.start()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()


def serve(host, port):
    global rs

    if rs:
        pyrebox_print("RAP server already running on {}:{}".format(rs.host, rs.port))
        return

    try:
        rs = RapServer(host, port)
        rs.serve()
        pyrebox_print("RAP server listening on {}:{}".format(host, port))
    except Exception as ex:
        pyrebox_print("RAP server error: {}".format(ex))


def shutdown():
    global rs

    if not rs:
        pyrebox_print("RAP server not running")
        return

    pyrebox_print("Closing RAP server (waiting for clients to disconnect)...")
    rs.shutdown()
    rs = None
    pyrebox_print("RAP server closed")


def do_rap(line):
    '''Start a radare2 RAP server

    Usage: custom rap :1234         - start a RAP server listening on localhost:1234
           custom rap 0.0.0.0:1234  - start a RAP server listening on 0.0.0.0:1234
           custom rap shutdown      - close the running RAP server
    '''

    elements = line.split(":")
    if len(elements) == 1 and elements[0] == "shutdown":
        # custom rap shutdown
        shutdown()
    elif len(elements) == 2:
        # custom rap [hostname]:port
        host = elements[0]
        port = int(elements[1])
        if host == "":
            host = "localhost"
        serve(host, port)
    else:
        # Unknown cmdline
        pyrebox_print(do_rap.__doc__)


def initialize_callbacks(module_hdl, printer):
    global pyrebox_print
    pyrebox_print = printer


def clean():
    shutdown()

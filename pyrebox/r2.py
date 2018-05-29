import SocketServer
import struct

import api
from utils import find_procs
from utils import pp_print
from utils import pp_debug
from utils import pp_warning
from utils import pp_error

class BaseRapHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        while True:
            try:
                self.handle_packet()
            except EOFError:
                pp_debug("Closed connection\n")
                break
            except Exception as e:
                pp_error("Protocol error: {}\n".format(e))
                break

    def handle_packet(self):
        buf = self.request.recv(1)

        if len(buf) == 0:
            raise EOFError

        packet_type = ord(buf)

        if packet_type == RapServer.RAP_OPEN:
            buf = self.request.recv(2)
            (flags, size) = struct.unpack(">BB", buf)
            name = self.request.recv(size)
            fd = self.rap_open(name, flags)
            buf = struct.pack(">BI", RapServer.RAP_OPEN|RapServer.RAP_REPLY, fd)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_READ:
            buf = self.request.recv(4)
            (size,) = struct.unpack(">I", buf)
            ret = self.rap_read(size)
            buf = struct.pack(">BI", RapServer.RAP_READ|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        elif packet_type == RapServer.RAP_WRITE:
            buf = self.request.recv(4)
            (size,) = struct.unpack(">I", buf)
            buf = self.request.recv(size)
            ret = self.rap_write(buf)
            buf = struct.pack(">BI", RapServer.RAP_WRITE|RapServer.RAP_REPLY, ret)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_SEEK:
            buf = self.request.recv(9)
            (whence, offset) = struct.unpack(">BQ", buf)
            ret = self.rap_seek(offset, whence)
            buf = struct.pack(">BQ", RapServer.RAP_SEEK|RapServer.RAP_REPLY, ret)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_CLOSE:
            buf = self.request.recv(4)
            (fd,) = struct.unpack(">I", buf)
            self.rap_close(fd)
            buf = struct.pack(">B", RapServer.RAP_CLOSE|RapServer.RAP_REPLY)
            self.request.sendall(buf)

        elif packet_type == RapServer.RAP_SYSTEM:
            buf = self.request.recv(4)
            (size,) = struct.unpack(">I", buf)
            buf = self.request.recv(size)
            ret = self.rap_system(buf)
            buf = struct.pack(">BI", RapServer.RAP_SYSTEM|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        elif packet_type == RapServer.RAP_CMD:
            buf = self.request.recv(4)
            (size,) = struct.unpack(">I", buf)
            buf = self.request.recv(size)
            ret = self.rap_cmd(buf)
            buf = struct.pack(">BI", RapServer.RAP_CMD|RapServer.RAP_REPLY, len(ret))
            self.request.sendall(buf + ret)

        else:
            raise "unknown RAP packet type"

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
        procs = find_procs(name)
        if len(procs) == 0:
            pp_warning("Process not found: {}\n".format(name))
            return 0

        (self.pid, self.pgd, self.pname) = procs[0]

        module_list = api.get_module_list(self.pgd)
        for m in module_list:
            if m["name"] != self.pname:
                continue
            self.base = m["base"]
            self.size = m["size"]

        pp_debug("Selecting name={} pid={} base={:#x} size={}\n".format(
            self.pid, self.pname, self.base, self.size))

        return 0

    def rap_read(self, size):
        try:
            data = api.r_va(self.pgd, self.curseek, size)
        except Exception:
            pp_error("Cannot read memory at {:#x}\n".format(self.curseek))
            data = ""

        return data

    def rap_write(self, data):
        try:
            api.w_va(self.pgd, self.curseek, data, len(data))
            size = len(data)
        except Exception:
            pp_error("Cannot write memory at {:#x}\n".format(self.curseek))
            size = 0

        return size

    def rap_seek(self, offset, whence):
        if whence == RapServer.RAP_SEEK_SET:
            self.curseek = offset
        elif whence == RapServer.RAP_SEEK_CUR:
            self.curseek = self.curseek + offset
        elif whence == RapServer.RAP_SEEK_END:
            self.curseek = self.base + self.size - offset

        return self.curseek

    def rap_close(self, fd):
        self.pid = 0
        self.pgd = 0
        self.pname = ""
        self.base = 0
        self.size = 0
        self.curseek = 0

    def rap_system(self, cmd):
        pp_debug("system not implemented\n")
        return ""

    def rap_cmd(self, cmd):
        pp_debug("cmd not implemented\n")
        return ""


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
        self.server = SocketServer.TCPServer((host, port), handler_class)

    def serve_forever(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()

# libslirp
A TCP-IP emulator as a library.

## Slirp

Originally designed to provide PPP/SLIP over terminal lines, slirp is a general purpose TCP-IP emulator widely used
by virtual machine hypervisors to provide virtual networking services.

Qemu, virtualbox, user-mode linux include slirp to provide the guest os with a virtual network while requiring no
configuration nor privileged services on the host.

This project wraps the slirp code in a library featuring a clean and simple interface.

## Install libslirp:

```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## libslirp tutorial

The first operation to use a slirp virtual network is <code>slirp_open</code>.
```
SLIRP *myslirp = slirp_open(SLIRP_IPV4 | SLIRP_IPV6);
```

*myslirp* is the descriptor of the slirp network.

The library has been designed to assign suitable default values for all the parameters:
* default route: 10.0.2.2/24
* DNS forward: 10.0.2.3
* DHCP addresses: 10.0.2.15 - 10.0.2.31
* default route ipv6: fe80::2/64
* DNS forward IPv6: fe80::3
* Virtual Router Advertisement daemon: active.

Libslirp provides functions to override the values (see <code>man libslirpcfg</code>).

After the (eventual) configuration of all the parameters the slirp network can be activated:
```
slirp_start(myslirp);
```

Now virtual networking (ethernet) packets can be sent and received using *slirp_send* and *slirp_recv*. e.g.:
```
sentlen = slirp_send(myslirp, pkt, pktlen);
pktlen = slirp_recv(myslirp, buf, buflen);
```

*slirp_fd* returns a file descriptor which can be used to wait for incoming packets using poll or select.
```
myslirpfd = slirp_fd(myslirp);
```

It is also possible to set up port forwarding for TCP, UDP (currently IPV4 only) or connect X-window clients
running in the virtual network to a X server UNIX socket, see <code>man libslirpfwd</code>.

To terminate the slirp network, call:
```
slirp_close(myslirp)
```

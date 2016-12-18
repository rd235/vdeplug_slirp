# vdeplug_slirp

This is the libvdeplug plugin module to join slirp networks.
It is based on the [libslirp](https://github.com/rd235/libslirp) library.

This module of libvdeplug4 can be used in any program supporting VDE like vde_plug, kvm, qemu, user-mode-linux and virtualbox.

## install vdeplug_slirp

Requirements: [vdeplug4](https://github.com/rd235/vdeplug4) and [libslirp](https://github.com/rd235/libslirp).

vdeplug_slirp uses the auto-tools, so the standard procedure to build and install
this vdeplug plugin module is the following:

```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## usage examples (tutorial)

### connect a vxvde network to the Internet using slirp

```
vde_plug vxvde:// slirp://
```

### connect a tap virtual interface to slirp with port forwarding

* TCP port 8080 is forwarded to port 80 of 10.0.2.15
* X-window display 10.0.2.2:0 is forwarded to the local X server.

```
vde_plug tap://mytap slirp:///tcpfwd=8080:10.0.2.15:80/unixfwd=6000:\"/tmp/.X11-unix/0\"
```

### connect a kvm machine to the Internet using slirp (both v4 and v6)
```
kvm .... -device e1000,netdev=vde0,mac=52:54:00:00:00:01 -netdev vde,id=vde0,sock="slirp:///v4/v6"
```

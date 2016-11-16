/*
 * VDE - libvdeplug_slirp modules 
 * Copyright (C) 2016 Renzo Davoli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libvdeplug_mod.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <libslirp.h>

static VDECONN *vde_slirp_open(char *sockname, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_slirp_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_slirp_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_slirp_datafd(VDECONN *conn);
static int vde_slirp_ctlfd(VDECONN *conn);
static int vde_slirp_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_slirp_open,
	.vde_recv=vde_slirp_recv,
	.vde_send=vde_slirp_send,
	.vde_datafd=vde_slirp_datafd,
	.vde_ctlfd=vde_slirp_ctlfd,
	.vde_close=vde_slirp_close
};

struct vde_slirp_conn {
	void *handle;
	struct vdeplug_module *module;

	SLIRP *slirp;
};

/* optimization O2 generates fake warnings */
static void vde_slirp_dofwd(SLIRP *slirp, int is_udp, char *arg) __attribute__((optimize("-O1")));
static void vde_slirp_dofwd(SLIRP *slirp, int is_udp, char *arg) {
	char *toktmp;
	char *fwditem;
	while ((fwditem = strtok_r(arg, ",", &toktmp)) != NULL) {
		char *fldtmp;
		char *haddrstr, *hport, *gaddrstr, *gport;
		struct in_addr host_addr, guest_addr;
		arg = NULL;

		haddrstr = strtok_r(fwditem, ":", &fldtmp);
		hport = strtok_r(NULL, ":", &fldtmp);
		gaddrstr = strtok_r(NULL, ":", &fldtmp);
		gport = strtok_r(NULL, ":", &fldtmp);
		if (gport == NULL) {
			gport = gaddrstr;
			gaddrstr = hport;
			hport = haddrstr;
			haddrstr = "0.0.0.0";
		}

		if (inet_pton(AF_INET, haddrstr, &host_addr) == 1 &&
				inet_pton(AF_INET, gaddrstr, &guest_addr) == 1)
			slirp_add_fwd(slirp, is_udp, 
					host_addr, atoi(hport),
					guest_addr, atoi(gport)); 
	}
}

static void vde_slirp_dounixfwd(SLIRP *slirp, char *arg) __attribute__((optimize("-O1")));
static void vde_slirp_dounixfwd(SLIRP *slirp, char *arg) {
	char *toktmp;
	char *fwditem;
	while ((fwditem = strtok_r(arg, ",", &toktmp)) != NULL) {
		char *fldtmp;
		char *haddrstr, *hport, *path;
		struct in_addr host_addr;
		arg = NULL;

		haddrstr = strtok_r(fwditem, ":", &fldtmp);
		hport = strtok_r(NULL, ":", &fldtmp);
		path = strtok_r(NULL, ":", &fldtmp);
		if (path == NULL) {
			path = hport;
			hport = haddrstr;
			haddrstr = "0.0.0.0";
		}
		if (inet_pton(AF_INET, haddrstr, &host_addr) == 1 &&
				path != 0)
			slirp_add_unixfwd(slirp, host_addr, atoi(hport), path);
	}
}

static VDECONN *vde_slirp_open(char *sockname, char *descr,int interface_version,
		struct vde_open_args *open_args) {
	struct vde_slirp_conn *newconn = NULL;
	char *v6str = NULL;
	char *v4str = NULL;
	char *vhostname = "slirp";
	char *tftp_path = NULL;
	char *bootfile = NULL;
	char *host4 = NULL;
	char *host6 = NULL;
	char *dhcp = NULL;
	char *tcpfwd = NULL;
	char *udpfwd = NULL;
	char *unixfwd = NULL;
	struct addrinfo hints;
	struct addrinfo *result;
	char *suffix;
	SLIRP *slirp;
	uint32_t flags = 0;
	struct vdeparms parms[] = {
		{"v4", &v4str},
		{"v6", &v6str},
		{"hostname", &vhostname},
		{"tftp_path", &tftp_path},
		{"bootfile", &bootfile},
		{"addr", &host4},
		{"addr6", &host6},
		{"dhcp", &dhcp},
		{"tcpfwd", &tcpfwd},
		{"udpfwd", &udpfwd},
		{"unixfwd", &unixfwd},
		{NULL, NULL}};

	memset(&hints, 0, sizeof(struct addrinfo));
	if (vde_parseparms(sockname, parms) != 0)
		return NULL;

	if (v4str) flags |= SLIRP_IPV4;
	if (v6str) flags |= SLIRP_IPV6;
	slirp = slirp_open(flags);

	if (host4) {
		int prefix = 24;
		int n;
		if ((suffix = strchr(host4, '/')) != NULL) {
			*suffix = 0;
			prefix = atoi(suffix+1);
		} 
		hints.ai_family = AF_INET;
		if ((n = getaddrinfo(host4, "0", &hints, &result)) < 0) {
			fprintf(stderr, "addr getaddrinfo: %s\n", gai_strerror(n));
			goto addrinfo_err;
		}
		slirp_set_addr(slirp, ((struct sockaddr_in *)(result->ai_addr)) -> sin_addr, prefix);
		freeaddrinfo(result);
	}

	if (host6) {
		int prefix = 64;
		int n;
		if ((suffix = strchr(host6, '/')) != NULL) {
			*suffix = 0;
			prefix = atoi(suffix+1);
		}
		hints.ai_family = AF_INET6;
		if ((n = getaddrinfo(host6, "0", &hints, &result)) < 0) { 
			fprintf(stderr, "addr getaddrinfo: %s\n", gai_strerror(n));
			goto addrinfo_err;
		}
		slirp_set_addr6(slirp, ((struct sockaddr_in6 *)(result->ai_addr)) -> sin6_addr, prefix);
		freeaddrinfo(result);
	}

	if (dhcp) {
		int n;
		hints.ai_family = AF_INET;
		if ((n = getaddrinfo(dhcp, "0", &hints, &result)) < 0) {
			fprintf(stderr, "addr getaddrinfo: %s\n", gai_strerror(n));
			goto addrinfo_err;
		}
		slirp_set_dhcp(slirp, ((struct sockaddr_in *)(result->ai_addr)) -> sin_addr);
		freeaddrinfo(result);
	}

	if (vhostname)
		if (slirp_set_hostname(slirp, vhostname) < 0)
			goto slirp_err;

	if (tftp_path)
		if (slirp_set_tftppath(slirp, tftp_path) < 0)
			goto slirp_err;

	if (bootfile)
		if (slirp_set_bootfile(slirp, bootfile) < 0)
			goto slirp_err;

	if (slirp_start(slirp) == 0) {
		newconn = calloc(1, sizeof(*newconn));
		newconn -> slirp = slirp;
		if (tcpfwd)
			vde_slirp_dofwd(slirp, 0, tcpfwd);
		if (udpfwd)
			vde_slirp_dofwd(slirp, 1, udpfwd);
		if (unixfwd)
			vde_slirp_dounixfwd(slirp, unixfwd);
	} else
		goto slirp_err;
	return (VDECONN *) newconn;

addrinfo_err:
	freeaddrinfo(result);
slirp_err:
	slirp_close(slirp);
	return NULL;
}

static ssize_t vde_slirp_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return slirp_recv(vde_conn->slirp, buf, len);
}

static ssize_t vde_slirp_send(VDECONN *conn,const void *buf,size_t len,int flags) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return slirp_send(vde_conn->slirp, buf, len);
}

static int vde_slirp_datafd(VDECONN *conn) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	return slirp_fd(vde_conn->slirp);
}

static int vde_slirp_ctlfd(VDECONN *conn) {
	return -1;
}

static int vde_slirp_close(VDECONN *conn) {
	struct vde_slirp_conn *vde_conn = (struct vde_slirp_conn *)conn;
	int rval = slirp_close(vde_conn->slirp);
	if (rval == 0)
		free(vde_conn);
	return 0;
}


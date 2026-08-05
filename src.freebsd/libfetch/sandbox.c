/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libfetch sandbox broker (port extension, no FreeBSD equivalent).
 *
 * libfetch's risk boundary is its hand-written protocol parsers, fed
 * by server-controlled bytes.  A naive "staged" sandbox would have to
 * leave connect(2) available for redirects and FTP PASV -- an
 * arbitrary exfil/SSRF channel plus a readable filesystem to feed it.
 *
 * Instead, fetch_sandbox_begin() splits the process in two:
 *
 *   - a broker process (unfettered) that resolves and connects on
 *     request, returning connected fds over a SEQPACKET socketpair
 *     (SCM_RIGHTS);
 *   - the fetch process, which then enters the path-scoped sandbox
 *     (caph_enter_paths): no connect, no exec, no new sockets, and the
 *     filesystem confined to the output directory + TMPDIR.  TLS trust
 *     material is preloaded before entering (common.c).
 *
 * Redirects and PASV data channels go through the broker; the SOCKS5
 * and HTTP CONNECT handshakes stay in-process (they are parser code
 * and belong in the sandbox).  FTP active mode cannot work (needs
 * bind/listen); ftp.c falls back to PASV on its own.
 *
 * Broker policy: connects are restricted to ports 21, 80, 443 and
 * 8080; everything else fails closed.  ASTROUTILS_SANDBOX=NONE makes
 * fetch_sandbox_begin() a no-op (fetch_connect goes direct).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <capsicum_helpers.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fetch.h"
#include "common.h"

#define BROKER_MAXHOST 256

struct broker_req {
	int af;			/* AF_UNSPEC/AF_INET/AF_INET6 */
	int port;
	char host[BROKER_MAXHOST];
};

static const int broker_ports[] = { 21, 80, 443, 8080 };
static int broker_first_port;

static int broker_fd = -1;
static pid_t broker_pid = -1;

int
fetch_sandbox_active(void)
{
	return broker_fd >= 0;
}

/* ------------------------------------------------------------------ */
/* broker side (unfettered)                                            */
/* ------------------------------------------------------------------ */

static int
broker_port_ok(int port)
{
	size_t i;

	for (i = 0; i < sizeof(broker_ports) / sizeof(broker_ports[0]); i++)
		if (broker_ports[i] == port)
			return 1;
	/*
	 * The first connect pins its port: a mirror on a custom port
	 * works, and redirects off that host's port to another custom
	 * port fail closed.
	 */
	if (broker_first_port == 0) {
		broker_first_port = port;
		return 1;
	}
	return broker_first_port == port;
}

static int
broker_connect_one(const struct broker_req *req)
{
	struct addrinfo hints, *sais = NULL, *sai, *cais = NULL, *cai;
	const char *bindaddr;
	char service[16];
	int sd = -1, err, eai;

	if (!broker_port_ok(req->port)) {
		errno = EACCES;
		return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = req->af;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%d", req->port);
	eai = getaddrinfo(req->host, service, &hints, &sais);
	if (eai != 0) {
		errno = EHOSTUNREACH;
		return -1;
	}

	/* honor FETCH_BIND_ADDRESS, as fetch_connect() does */
	bindaddr = getenv("FETCH_BIND_ADDRESS");
	if (bindaddr != NULL && *bindaddr != '\0') {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = req->af;
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(bindaddr, NULL, &hints, &cais) != 0)
			cais = NULL;
	}

	for (sai = sais; sai != NULL; sai = sai->ai_next) {
		sd = socket(sai->ai_family, SOCK_STREAM, 0);
		if (sd < 0)
			continue;
		for (cai = cais; cai != NULL; cai = cai->ai_next) {
			if (cai->ai_family != sai->ai_family)
				continue;
			if (bind(sd, cai->ai_addr, cai->ai_addrlen) == 0)
				break;
		}
		err = connect(sd, sai->ai_addr, sai->ai_addrlen);
		if (err == 0)
			break;
		close(sd);
		sd = -1;
	}
	if (cais != NULL)
		freeaddrinfo(cais);
	if (sais != NULL)
		freeaddrinfo(sais);
	return sd;
}

static void
broker_send_result(int fd, int status, int payload_fd)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} ctrl;
	struct cmsghdr *cmsg;

	iov.iov_base = &status;
	iov.iov_len = sizeof(status);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (payload_fd >= 0) {
		msg.msg_control = ctrl.buf;
		msg.msg_controllen = sizeof(ctrl.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &payload_fd, sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;
	}
	(void)sendmsg(fd, &msg, 0);
	if (payload_fd >= 0)
		(void)close(payload_fd);
}

static void
broker_loop(int fd)
{
	struct broker_req req;
	ssize_t n;
	int sd, status;

	for (;;) {
		n = recv(fd, &req, sizeof(req), 0);
		if (n != (ssize_t)sizeof(req))
			break;	/* fetch process went away */
		req.host[BROKER_MAXHOST - 1] = '\0';
		sd = broker_connect_one(&req);
		status = sd >= 0 ? 0 : errno;
		broker_send_result(fd, status, sd);
	}
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* fetch-process side (enters the sandbox)                             */
/* ------------------------------------------------------------------ */

int
fetch_sandbox_connect(const char *host, int port, int af)
{
	struct broker_req req;
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} ctrl;
	struct cmsghdr *cmsg;
	int status = 0, sd = -1;
	ssize_t n;

	if (broker_fd < 0) {
		errno = ENOSYS;
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.af = af;
	req.port = port;
	if (strlen(host) >= sizeof(req.host)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(req.host, host);
	if (send(broker_fd, &req, sizeof(req), 0) != (ssize_t)sizeof(req)) {
		errno = EPIPE;
		return -1;
	}

	iov.iov_base = &status;
	iov.iov_len = sizeof(status);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl.buf;
	msg.msg_controllen = sizeof(ctrl.buf);
	n = recvmsg(broker_fd, &msg, 0);
	if (n <= 0) {
		errno = EPIPE;
		return -1;
	}
	if (status != 0) {
		errno = status;
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS) {
		errno = EPROTO;
		return -1;
	}
	memcpy(&sd, CMSG_DATA(cmsg), sizeof(int));
	return sd;
}

int
fetch_sandbox_begin(const char *dir)
{
	const char *e = getenv("ASTROUTILS_SANDBOX");
	const char *tmp;
	int sp[2];
	pid_t pid;

	if (e != NULL && strcmp(e, "NONE") == 0)
		return 0;
	if (broker_fd >= 0)
		return 0;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}
	if (pid == 0) {
		/*
		 * Broker in the child: fetch's exit status reaches the
		 * caller (the broker _exit()s on socketpair EOF when the
		 * parent dies), instead of masking it behind a 0.
		 */
		close(sp[1]);
		broker_loop(sp[0]);
		/* NOTREACHED */
		_exit(0);
	}
	close(sp[0]);
	broker_fd = sp[1];
	broker_pid = pid;

	fetch_ssl_preload();

	tmp = getenv("TMPDIR");
	if (tmp == NULL || *tmp == '\0')
		tmp = "/tmp";
	if (caph_allow_path(dir) < 0 ||
	    caph_allow_path(tmp) < 0 ||
	    caph_enter_paths() < 0) {
		int err = errno;
		(void)kill(broker_pid, SIGKILL);
		(void)waitpid(broker_pid, NULL, 0);
		close(broker_fd);
		broker_fd = -1;
		errno = err;
		return -1;
	}
	return 0;
}

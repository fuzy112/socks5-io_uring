/* socks.c
 *
 * Copyright 2022 Zhengyi Fu <tsingyat@outlook.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE

#include <errno.h>
#include <liburing.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "circ_buf.h"
#include "container_of.h"
#include "list.h"

#define SOCKS_PROTO_VERSION 0x05
#define SOCKS_AUTH_NO_AUTH 0x00

#define BUFFER_SIZE (1u << 14)

#define QUEUE_DEPTH 64

// #define DEBUG 1

#if DEBUG
#define trace_callback()                                                       \
	do {                                                                   \
		fprintf(stderr, "%s: %p, %d, %#08x\n", __func__, data, res,    \
			flags);                                                \
	} while (0)

#define trace_function()                                                       \
	do {                                                                   \
		fprintf(stderr, "%s\n", __func__);                             \
	} while (0)

#else
#define trace_callback() (void)0
#define trace_function() (void)0
#endif

#ifdef __GNUC__
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

static void vprint_errmsg(int errnum, const char *__restrict fmt, va_list ap)
{
	char msg[500] = { '\0' };
	char buffer[512] = { '\0' };

	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	snprintf(buffer, sizeof(buffer), "%s: %s [%i]", msg, strerror(errnum),
		 errnum);

	fflush(stdout);
	fputs(buffer, stderr);
}

static void NORETURN err_exit(const char *__restrict fmt, ...)
{
	int errnum = errno;
	va_list ap;

	va_start(ap, fmt);
	vprint_errmsg(errnum, fmt, ap);
	va_end(ap);

#ifdef DEBUG
	abort();
#endif
	exit(EXIT_FAILURE);
}

static void NORETURN err_exit_n(int errnum, const char *__restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprint_errmsg(errnum, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

static void NORETURN fatal(const char *__restrict fmt, ...)
{
	char buffer[500] = { '\0' };
	va_list ap;

	fflush(stdout);

	va_start(ap, fmt);
	snprintf(buffer, sizeof(buffer) - 1, fmt, ap);
	va_end(ap);

	fputs(buffer, stderr);

#ifdef DEBUG
	abort();
#endif
	exit(EXIT_FAILURE);
}

typedef void (*completion_callback)(void *, int, unsigned);

struct op_data {
	completion_callback callback;
	struct list_head list;
};

struct io_data {
	struct op_data op_data;
	struct iovec iovecs[2];
};

struct accept_data {
	struct op_data op_data;
	struct sockaddr_storage addr;
	socklen_t addrlen;
};

struct connect_data {
	struct op_data op_data;
	struct sockaddr_storage addr;
};

struct handshake_session;

struct connector {
	struct io_uring *ring;
	struct handshake_session *client;

	int sock;
	struct connect_data connect_op;
};
static void connector_connect_callback(void *data, int res, unsigned flags);
static int connecting_do_connect(struct connector *ses,
				 const struct sockaddr *addr,
				 socklen_t addrlen);

static struct connector *connector_new(struct io_uring *ring,
				       struct handshake_session *client,
				       sa_family_t family);
static void connector_free(struct connector *);

enum address_type {
	ATYP_IPv4 = 0x01,
	ATYP_DOMAINNAME = 0x03,
	ATYP_IPV6 = 0x04,
};

enum request_status {
	STATUS_REQUEST_GRANTED = 0x00,
	STATUS_GENERAL_FAILURE = 0x01,
	STATUS_NOT_ALLOWED = 0x02,
	STATUS_NETWORK_UNREACHABLE = 0x03,
	STATUS_HOST_UNREACHABLE = 0x04,
	STATUS_CONNECTION_REFUSED = 0x05,
	STATUS_TTL_EXPIRED = 0x06,
	STATUS_COMMAND_NOT_SUPPORTED = 0x07,
	STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

struct handshake_session {
	struct io_uring *ring;
	int sock;
	int ref;

	int (*state_fn)(struct handshake_session *);

	struct connector *remote;

	struct io_data read_op;
	struct io_data write_op;

	struct circ_buf *read_buf;
	struct circ_buf *write_buf;
};

enum handshake_state_rc {
	HS_OK,
	HS_NEED_MORE,
	HS_CLOSE,
};

static int handshake_state_greet(struct handshake_session *);
static int handshake_state_auth(struct handshake_session *);
static int handshake_state_request(struct handshake_session *);
static int handshake_state_finish(struct handshake_session *);
static int handshake_state_error(struct handshake_session *);

static void handshake_read_callback(void *data, int res, unsigned flags);
static void handshake_write_callback(void *data, int res, unsigned flags);

static void handshake_do_write(struct handshake_session *ses);
static void handshake_do_read(struct handshake_session *ses);

static struct handshake_session *
handshake_session_new_from_socket(struct io_uring *, int sock);
static void handshake_session_ref(struct handshake_session *);
static void handshake_session_unref(struct handshake_session *);

struct tunnel_session;

struct tunnel_connection {
	struct io_uring *ring;
	struct tunnel_session *owner;
	struct tunnel_connection *other;

	int sock;

	unsigned is_client : 1;

	unsigned readable : 1;
	unsigned writable : 1;

	struct circ_buf *read_buf;
	struct circ_buf *write_buf;

	struct io_data read_op;
	struct io_data write_op;
	struct op_data shutdown_op;
};

static void tunnel_connection_init(struct tunnel_connection *conn,
				   struct tunnel_session *owner,
				   struct tunnel_connection *other, int sock,
				   struct circ_buf *read_buf,
				   struct circ_buf *write_buf);

static void tunnel_connection_exit(struct tunnel_connection *conn);

struct tunnel_session {
	struct io_uring *ring;

	struct tunnel_connection client;
	struct tunnel_connection remote;

	int ref;

	struct circ_buf *client_read_buf;
	struct circ_buf *remote_read_buf;
};

static struct tunnel_session *tunnel_session_ref(struct tunnel_session *);

static void tunnel_session_unref(struct tunnel_session *);

static void tunnel_read_callback(void *data, int res, unsigned flags);
static void tunnel_write_callback(void *data, int res, unsigned flags);
static void tunnel_shutdown_callback(void *data, int res, unsigned flags);

static void tunnel_do_read(struct tunnel_connection *);
static void tunnel_do_write(struct tunnel_connection *);
static void tunnel_do_shutdown(struct tunnel_connection *, int how);

static struct tunnel_session *tunnel_session_new(struct handshake_session *);

static void tunnel_start(struct tunnel_session *);

struct listener {
	struct io_uring *ring;
	int sock;

	struct accept_data accept_op;

	int ref;
};

static void listener_accept_callback(void *data, int res, unsigned flags);

static struct listener *listener_new(struct io_uring *ring,
				     const struct sockaddr *addr,
				     socklen_t addrlen);
static void listener_ref(struct listener *);
static void listener_unref(struct listener *);

static int listener_do_accept(struct listener *);

static void dump_iovecs(struct iovec *, unsigned, unsigned);

static LIST_HEAD(submitted_ops);

static void submit_cancellable_op(struct io_uring *ring, struct op_data *op)
{
	int s;

#ifdef DEBUG
	struct op_data *entry;
	list_for_each_entry (entry, &submitted_ops, list) {
		if (entry == op)
			abort ();
	}
#endif
	
	list_add_tail(&op->list, &submitted_ops);

	s = io_uring_submit(ring);
	if (s < 0)
		err_exit_n(s, "io_uring_submit");
}

/********************************************************************
 * Listener
 ********************************************************************/

struct listener *listener_new(struct io_uring *ring,
			      const struct sockaddr *addr, socklen_t addrlen)
{
	struct listener *l;
	int reuse_addr = 1;
	int err = 0;

	l = calloc(1, sizeof(struct listener));
	if (!l)
		return NULL;

	l->ring = ring;
	l->accept_op.op_data.callback = listener_accept_callback;

	l->sock = socket(addr->sa_family, SOCK_STREAM, 0);
	if (l->sock == -1) {
		err = errno;
		goto err_free_mem;
	}
	if (setsockopt(l->sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
		       sizeof(reuse_addr)) < 0) {
		err = errno;
		goto err_close_sock;
	}
	if (bind(l->sock, addr, addrlen) < 0) {
		err = errno;
		goto err_close_sock;
	}
	if (listen(l->sock, 32) < 0) {
		err = errno;
		goto err_close_sock;
	}

	l->ref = 1;

	return l;

err_close_sock:
	close(l->sock);

err_free_mem:
	free(l);

	errno = err;
	return NULL;
}

void listener_ref(struct listener *l)
{
	l->ref++;
}

void listener_unref(struct listener *l)
{
	if (--l->ref != 0)
		return;

	close(l->sock);
	free(l);
}

int listener_do_accept(struct listener *l)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(l->ring);
	if (!sqe) {
		return -EBUSY;
	}

	io_uring_prep_accept(sqe, l->sock,
			     (struct sockaddr *)&l->accept_op.addr,
			     &l->accept_op.addrlen, 0);
	io_uring_sqe_set_data(sqe, &l->accept_op);
	submit_cancellable_op(l->ring, &l->accept_op.op_data);

	listener_ref(l);
	return 0;
}

void listener_accept_callback(void *data, int res, unsigned flags)
{
	struct accept_data *accept_op = data;
	struct listener *l =
		container_of(accept_op, struct listener, accept_op);
	(void)flags;

	trace_callback();

	assert(accept_op);

	if (res < 0) {
		fprintf(stderr, "accept: %s\n", strerror(-res));
		if (res == -ECANCELED)
			goto out;
	} else {
		struct handshake_session *ses =
			handshake_session_new_from_socket(l->ring, res);
		if (ses) {
			handshake_do_read(ses);
			handshake_session_unref(ses);
		}
	}

	listener_do_accept(l);

out:
	listener_unref(l);
}

/********************************************************************
 * Handshake
 ********************************************************************/

struct handshake_session *
handshake_session_new_from_socket(struct io_uring *ring, int sock)
{
	struct handshake_session *ses;

	assert(ring);
	assert(sock > 0);

	ses = calloc(1, sizeof(*ses) + BUFFER_SIZE);
	if (!ses)
		return NULL;

	ses->ring = ring;
	ses->sock = sock;
	ses->ref = 1;
	ses->read_buf = circ_buf_alloc(BUFFER_SIZE);
	if (ses->read_buf == NULL)
		goto err_free_ses;

	ses->write_buf = circ_buf_alloc(BUFFER_SIZE);
	if (ses->write_buf == NULL)
		goto err_free_read_buf;

	ses->state_fn = handshake_state_greet;
	ses->remote = NULL;

	ses->read_op.op_data.callback = handshake_read_callback;
	ses->write_op.op_data.callback = handshake_write_callback;

	return ses;

err_free_read_buf:
	free(ses->read_buf);

err_free_ses:
	free(ses);

	errno = ENOMEM;
	return 0;
}

void handshake_session_ref(struct handshake_session *ses)
{
	ses->ref++;
}

void handshake_session_unref(struct handshake_session *ses)
{
	if (--ses->ref != 0) {
		return;
	}
	free(ses->read_buf);
	free(ses->write_buf);
	connector_free(ses->remote);
	if (ses->sock > 0)
		close(ses->sock);
	free(ses);
}

void handshake_do_read(struct handshake_session *ses)
{
	struct io_uring_sqe *sqe;
	unsigned nr_vecs = 0;

	sqe = io_uring_get_sqe(ses->ring);
	if (!sqe)
		err_exit("io_uring_get_sqe");

	circ_buf_prepare(ses->read_buf, ses->read_op.iovecs, &nr_vecs);

	io_uring_prep_readv(sqe, ses->sock, ses->read_op.iovecs, nr_vecs, 0);
	io_uring_sqe_set_data(sqe, &ses->read_op);

	submit_cancellable_op(ses->ring, &ses->read_op.op_data);

	handshake_session_ref(ses);
}

void handshake_do_write(struct handshake_session *ses)
{
	struct io_uring_sqe *sqe;
	unsigned nr_vecs = 0;

	sqe = io_uring_get_sqe(ses->ring);
	if (!sqe)
		err_exit("io_uring_get_sqe");

	circ_buf_data(ses->write_buf, ses->write_op.iovecs, &nr_vecs);

	io_uring_prep_writev(sqe, ses->sock, ses->write_op.iovecs, nr_vecs, 0);
	io_uring_sqe_set_data(sqe, &ses->write_op);

	submit_cancellable_op(ses->ring, &ses->write_op.op_data);
	handshake_session_ref(ses);
}

void handshake_read_callback(void *data, int res, unsigned flags)
{
	struct io_data *read_op = data;
	struct handshake_session *ses =
		container_of(read_op, struct handshake_session, read_op);
	(void)flags;

	trace_callback();

	assert(read_op);
	assert(ses);

	if (res < 0) {
		fprintf(stderr, "handshake_read: %s\n", strerror(-res));
		goto out;
	}

	if (res == 0) {
		fprintf(stderr, "client closed connection\n");
		goto out;
	}

	circ_buf_commit(ses->read_buf, res);

	assert(ses->state_fn);

	switch (ses->state_fn(ses)) {
	case HS_OK:
		if (!circ_buf_empty(ses->read_buf)) {
			ses->state_fn = handshake_state_error;
		}
		break;

	case HS_CLOSE:
		break;

	case HS_NEED_MORE:
		if (circ_buf_empty(ses->write_buf))
			handshake_do_read(ses);
		break;
	}

out:
	handshake_session_unref(ses);
}

void handshake_write_callback(void *data, int res, unsigned flags)
{
	struct io_data *write_op = data;
	struct handshake_session *ses =
		container_of(write_op, struct handshake_session, write_op);
	(void)flags;

	trace_callback();
	assert(data);

	if (res < 0) {
		fprintf(stderr, "handshake_write: %s\n", strerror(-res));

		ses->state_fn = handshake_state_error;
		ses->write_buf->head = ses->write_buf->tail;
		goto out;
	} else
		circ_buf_consume(ses->write_buf, res);

	if (circ_buf_empty(ses->write_buf))
		handshake_do_read(ses);
	else
		handshake_do_write(ses);

out:
	handshake_session_unref(ses);
}

int handshake_state_greet(struct handshake_session *ses)
{
	uint8_t ver = 0;
	uint8_t nr_methods = 0;
	uint8_t methods[255] = { 0 };

	unsigned off = 0;
	unsigned i;
	int is_writing;

	if (circ_buf_read_u8(ses->read_buf, &ver, &off) ||
	    circ_buf_read_u8(ses->read_buf, &nr_methods, &off) ||
	    circ_buf_read(ses->read_buf, methods, nr_methods, &off))
		return HS_NEED_MORE;

	circ_buf_consume(ses->read_buf, off);

	if (ver != SOCKS_PROTO_VERSION) {
		fprintf(stderr, "invalid protocol version: %#02x\n", ver);
		ses->state_fn = handshake_state_error;
		return HS_OK;
	}

	for (i = 0; i < nr_methods; ++i) {
		if (methods[i] == SOCKS_AUTH_NO_AUTH) {
			break;
		}
	}

	if (i >= nr_methods) {
		fprintf(stderr, "no method supported\n");
		ses->state_fn = handshake_state_error;
		return HS_OK;
	}

	// prepare write data
	off = 0;

	is_writing = !circ_buf_empty(ses->write_buf);

	if (circ_buf_write_u8(ses->write_buf, SOCKS_PROTO_VERSION, &off) ||
	    circ_buf_write_u8(ses->write_buf, methods[i], &off)) {
		fatal("circ_buf_write");
	}

	circ_buf_commit(ses->write_buf, off);

	if (!is_writing)
		handshake_do_write(ses);

	if (methods[i] == SOCKS_AUTH_NO_AUTH) {
		ses->state_fn = handshake_state_request;
	} else {
		ses->state_fn = handshake_state_auth;
	}
	return HS_OK;
}

int handshake_state_auth(struct handshake_session *ses)
{
	fprintf(stderr, "authentication is not implemented\n");
	ses->state_fn = handshake_state_error;
	return HS_OK;
}

static int handshake_response_error(struct handshake_session *ses, __u8 status)
{
	unsigned off = 0;

	__u8 zeros[8] = { '\0' };

	int is_writing = !circ_buf_empty(ses->write_buf);

	fprintf(stderr, "handshake_error: %#02x\n", status);

	if (circ_buf_write_u8(ses->write_buf, SOCKS_PROTO_VERSION, &off) ||
	    circ_buf_write_u8(ses->write_buf, status, &off) ||
	    circ_buf_write(ses->write_buf, zeros, 8, &off))
		fatal("circ_buf_write");

	circ_buf_commit(ses->write_buf, off);
	ses->state_fn = handshake_state_error;

	if (!is_writing)
		handshake_do_write(ses);
	return HS_NEED_MORE;
}

static void handshake_response_success(struct handshake_session *ses,
				       const struct sockaddr *addr,
				       socklen_t addrlen)
{
	unsigned off = 0;
	__u8 atyp = 0;
	int is_writing = 0;

	assert(ses);
	assert(addr);
	assert(addrlen >= sizeof(struct sockaddr));

	if (addr->sa_family == AF_INET6)
		atyp = ATYP_IPV6;
	else if (addr->sa_family == AF_INET)
		atyp = ATYP_IPv4;
	else
		fatal("unknown address type");

	is_writing = !circ_buf_empty(ses->write_buf);

	if (circ_buf_write_u8(ses->write_buf, SOCKS_PROTO_VERSION, &off) ||
	    circ_buf_write_u8(ses->write_buf, 0x00, &off) ||
	    circ_buf_write_u8(ses->write_buf, 0x00, &off) ||
	    circ_buf_write_u8(ses->write_buf, atyp, &off))
		fatal("circ_buf_write");

	assert(atyp == ATYP_IPv4);
	if (circ_buf_write(ses->write_buf, &addr->sa_data[2], 4, &off) ||
	    circ_buf_write(ses->write_buf, &addr->sa_data[0], 2, &off))
		fatal("circ_buf_write");

	circ_buf_commit(ses->write_buf, off);

	if (!is_writing)
		handshake_do_write(ses);
}

int handshake_state_request(struct handshake_session *ses)
{
	uint8_t ver = 0;
	uint8_t cmd = 0;
	uint8_t rsv = 0;
	uint8_t atyp = 0;

	struct sockaddr_storage addr = { 0 };
	socklen_t addrlen = sizeof(addr);

	__u16 port = 0;

	unsigned off = 0;

	struct connector *remote = NULL;

	trace_function();

	if (circ_buf_read_u8(ses->read_buf, &ver, &off) ||
	    circ_buf_read_u8(ses->read_buf, &cmd, &off) ||
	    circ_buf_read_u8(ses->read_buf, &rsv, &off) ||
	    circ_buf_read_u8(ses->read_buf, &atyp, &off))
		return HS_NEED_MORE;

	if (ver != SOCKS_PROTO_VERSION) {
		fprintf(stderr, "invalid protocol version: %#02x\n", ver);
		ses->state_fn = handshake_state_error;
		return HS_OK;
	}

	if (cmd != 0x01) {
		fprintf(stderr, "command not supported: %#02x\n", cmd);
		return handshake_response_error(ses,
						STATUS_COMMAND_NOT_SUPPORTED);
	}

	switch (atyp) {
	case ATYP_IPv4: {
		struct sockaddr_in *in_addr = (struct sockaddr_in *)&addr;
		in_addr->sin_family = AF_INET;
		if (circ_buf_read(ses->read_buf, &in_addr->sin_addr, 4, &off))
			return HS_NEED_MORE;
		if (circ_buf_read(ses->read_buf, &in_addr->sin_port, 2, &off))
			return HS_NEED_MORE;

		addrlen = sizeof(*in_addr);
		break;
	}

	case ATYP_DOMAINNAME: {
		uint8_t len = 0;
		char domainname[256] = "";
		struct addrinfo *ai = NULL;
		struct addrinfo hint = { 0 };
		char service[20] = "";
		int s = 0;

		if (circ_buf_read_u8(ses->read_buf, &len, &off) ||
		    circ_buf_read(ses->read_buf, domainname, len, &off) ||
		    circ_buf_read_be16(ses->read_buf, &port, &off))
			return HS_NEED_MORE;
		snprintf(service, sizeof(service) - 1, "%u", port);

		hint.ai_family = AF_UNSPEC;
		hint.ai_socktype = SOCK_STREAM;

		s = getaddrinfo(domainname, service, &hint, &ai);
		if (s != 0) {
			fprintf(stderr, "failed to get address: %s\n",
				gai_strerror(s));
			return handshake_response_error(
				ses, STATUS_HOST_UNREACHABLE);
		}

		memcpy(&addr, ai->ai_addr, ai->ai_addrlen);
		addrlen = ai->ai_addrlen;
		freeaddrinfo(ai);
		break;
	}

	default:
		fprintf(stderr, "address type not supported: %#02x\n", atyp);
		return handshake_response_error(
			ses, STATUS_ADDRESS_TYPE_NOT_SUPPORTED);
	}

	circ_buf_consume(ses->read_buf, off);
	off = 0;

	remote = connector_new(ses->ring, ses, addr.ss_family);
	if (!remote) {
		return handshake_response_error(ses, STATUS_GENERAL_FAILURE);
	}

	if (connecting_do_connect(remote, (const struct sockaddr *)&addr,
				  addrlen) < 0) {
		connector_free(remote);
		return handshake_response_error(ses, STATUS_GENERAL_FAILURE);
	}

	ses->remote = remote;
	ses->state_fn = handshake_state_finish;

	return HS_CLOSE;
}

int handshake_state_finish(struct handshake_session *ses)
{
	struct tunnel_session *tunnel;

	assert(ses->remote);

	trace_function();

	tunnel = tunnel_session_new(ses);

	if (tunnel) {
		tunnel_start(tunnel);
	}
	return HS_CLOSE;
}

int handshake_state_error(struct handshake_session *ses)
{
	trace_function();

	handshake_session_unref(ses);
	return HS_CLOSE;
}

/********************************************************************
 * Connecting
 ********************************************************************/

struct connector *connector_new(struct io_uring *ring,
				struct handshake_session *client,
				sa_family_t family)
{
	struct connector *ses;

	assert(ring);

	ses = calloc(1, sizeof(*ses));
	if (!ses)
		return NULL;

	ses->ring = ring;
	ses->connect_op.op_data.callback = connector_connect_callback;
	ses->client = client;
	ses->sock = socket(family, SOCK_STREAM, 0);

	if (ses->sock == -1) {
		int errsv = errno;
		free(ses);
		errno = errsv;
		return NULL;
	}

	return ses;
}

void connector_free(struct connector *ses)
{
	if (!ses)
		return;
	if (ses->sock > 0)
		close(ses->sock);
	free(ses);
}

void connector_connect_callback(void *data, int res, unsigned flags)
{
	struct connect_data *connect_op = data;
	struct connector *ses =
		container_of(connect_op, struct connector, connect_op);
	struct handshake_session *client;
	struct sockaddr_storage addr;
	socklen_t len;
	(void)flags;

	trace_callback();

	assert(data);

	client = ses->client;

	if (res < 0) {
		fprintf(stderr, "connect: %s\n", strerror(-res));
	}

	if (res == -ECONNREFUSED) {
		handshake_response_error(client, STATUS_CONNECTION_REFUSED);
		goto out;
	}
	if (res == -ENETUNREACH) {
		handshake_response_error(client, STATUS_NETWORK_UNREACHABLE);
		goto out;
	}
	if (res == -EHOSTUNREACH) {
		handshake_response_error(client, STATUS_HOST_UNREACHABLE);
		goto out;
	}
	if (res < 0) {
		handshake_response_error(client, STATUS_GENERAL_FAILURE);
		goto out;
	}
	len = sizeof(addr);
	memset(&addr, 0, len);
	if (getpeername(ses->sock, (struct sockaddr *)&addr, &len) < 0)
		err_exit("getpeername");

	handshake_response_success(client, (struct sockaddr *)&addr, len);

out:
	handshake_session_unref(client);
}

int connecting_do_connect(struct connector *ses, const struct sockaddr *addr,
			  socklen_t addrlen)
{
	struct io_uring_sqe *sqe = NULL;

	sqe = io_uring_get_sqe(ses->ring);
	if (!sqe)
		return -EBUSY;

	memcpy(&ses->connect_op.addr, addr, addrlen);

	io_uring_prep_connect(sqe, ses->sock,
			      (const struct sockaddr *)&ses->connect_op.addr,
			      addrlen);
	io_uring_sqe_set_data(sqe, &ses->connect_op);
	submit_cancellable_op(ses->ring, &ses->connect_op.op_data);

	handshake_session_ref(ses->client);

	return 0;
}

/********************************************************************
 * Tunnel
 *******************************************************************/

struct tunnel_session *tunnel_session_ref(struct tunnel_session *tunnel)
{
	assert(tunnel);
	tunnel->ref++;

	//   fprintf (stderr, "tunnel ref: %d\n", tunnel->ref);
	return tunnel;
}

void tunnel_session_unref(struct tunnel_session *tunnel)
{
	int n = --tunnel->ref;
	if (n != 0)
		return;

	tunnel_connection_exit(&tunnel->client);
	tunnel_connection_exit(&tunnel->remote);
	free(tunnel->remote_read_buf);
	free(tunnel->client_read_buf);

	fprintf(stderr, "tunnel released: %p\n", (void *)tunnel);

	free(tunnel);

	//   fprintf (stderr, "tunnel unref: %d\n", n);
}

void tunnel_read_callback(void *data, int res, unsigned flags)
{
	struct io_data *read_op = data;
	struct tunnel_connection *conn =
		container_of(read_op, struct tunnel_connection, read_op);
	int need_write;
	(void)flags;

	trace_callback();
	assert(data);

	if (res < 0) {
		fprintf(stderr, "tunnel_read: %s\n", strerror(-res));
		goto out;
	}

	if (res == 0) {
		//   tunnel_do_shutdown (conn, SHUT_RD);
		conn->readable = 0;
	}

	need_write = circ_buf_empty(conn->read_buf);

	circ_buf_commit(conn->read_buf, res);

	if (need_write) {
		if (res == 0) {
			tunnel_do_shutdown(conn->other, SHUT_WR);
		} else {
			tunnel_do_write(conn->other);
		}
	}

	if (circ_buf_space(conn->read_buf)) {
		tunnel_do_read(conn);
	}

out:
	tunnel_session_unref(conn->owner);
}

void tunnel_write_callback(void *data, int res, unsigned flags)
{
	struct io_data *write_op = data;
	struct tunnel_connection *conn =
		container_of(write_op, struct tunnel_connection, write_op);
	int need_read;
	(void)flags;

	trace_callback();

	if (res == -EPIPE) {
		tunnel_do_shutdown(conn->other, SHUT_RD);
		goto out;
	}
	if (res < 0) {
		fprintf(stderr, "tunnel_write: %s\n", strerror(-res));
		goto out;
	}

	need_read = circ_buf_space(conn->write_buf) == 0;

	circ_buf_consume(conn->write_buf, res);
	if (!circ_buf_empty(conn->write_buf)) {
		tunnel_do_write(conn);
	}

	if (need_read) {
		tunnel_do_read(conn->other);
	}

out:
	tunnel_session_unref(conn->owner);
}

void tunnel_shutdown_callback(void *data, int res, unsigned flags)
{
	struct op_data *shutdown_op = data;
	struct tunnel_connection *conn = container_of(
		shutdown_op, struct tunnel_connection, shutdown_op);
	(void)flags;

	trace_callback();
	assert(data);

	if (res < 0) {
		fprintf(stderr, "shutdown: %s\n", strerror(-res));
	}

	tunnel_session_unref(conn->owner);
}

#define DUMP_IOVEC_DATA (1u << 1)

static void __attribute__((unused))
dump_iovecs(struct iovec *iovecs, unsigned nr_vecs, unsigned flags)
{
	unsigned i, j;

	for (i = 0; i < nr_vecs; ++i) {
		fprintf(stderr,
			"iov[%i] = { .iov_base = %p, .iov_len = %zu }\n", i,
			iovecs[i].iov_base, iovecs[i].iov_len);

		if (flags & DUMP_IOVEC_DATA) {
			for (j = 0; j < iovecs[i].iov_len; ++j) {
				unsigned c = ((__u8 *)iovecs[i].iov_base)[j];
				fprintf(stderr, "%02x ", c);
			}

			fprintf(stderr, "\n");

			(void)write(STDERR_FILENO, iovecs[i].iov_base,
				    iovecs[i].iov_len);
			(void)write(STDERR_FILENO, "\n", 1);
		}
	}
}

void tunnel_do_read(struct tunnel_connection *conn)
{
	struct tunnel_session *tunnel = conn->owner;
	struct io_uring_sqe *sqe = NULL;
	unsigned nr_vecs = 0;

	assert(tunnel);

	assert(circ_buf_space(conn->read_buf));

	if (!conn->readable)
		return;

	sqe = io_uring_get_sqe(conn->ring);
	if (!sqe) {
		perror("io_uring_get_sqe");
		return;
	}

	circ_buf_prepare(conn->read_buf, conn->read_op.iovecs, &nr_vecs);

	io_uring_prep_readv(sqe, conn->sock, conn->read_op.iovecs, nr_vecs, 0);
	io_uring_sqe_set_data(sqe, &conn->read_op);
	submit_cancellable_op(conn->ring, &conn->read_op.op_data);

	tunnel_session_ref(tunnel);
}

void tunnel_do_write(struct tunnel_connection *conn)
{
	struct tunnel_session *tunnel = conn->owner;
	struct io_uring_sqe *sqe = NULL;
	unsigned nr_vecs = 0;

	assert(circ_buf_count(conn->write_buf));
	assert(tunnel);

	if (!conn->writable)
		return;

	sqe = io_uring_get_sqe(conn->ring);
	if (!sqe) {
		perror("io_uring_get_sqe");
		return;
	}

	circ_buf_data(conn->write_buf, conn->write_op.iovecs, &nr_vecs);

	io_uring_prep_writev(sqe, conn->sock, conn->write_op.iovecs, nr_vecs,
			     0);
	io_uring_sqe_set_data(sqe, &conn->write_op);
	submit_cancellable_op(conn->ring, &conn->write_op.op_data);

	tunnel_session_ref(tunnel);
}

void tunnel_do_shutdown(struct tunnel_connection *conn, int how)
{
	struct tunnel_session *tunnel = conn->owner;
	struct io_uring_sqe *sqe = NULL;

	switch (how) {
	case SHUT_RD:
		if (!conn->readable)
			return;
		conn->readable = 0;
		break;
	case SHUT_WR:
		if (!conn->readable)
			return;
		conn->writable = 0;
		break;
	case SHUT_RDWR:
		if (!conn->readable && !conn->writable)
			return;
		conn->readable = 0;
		conn->writable = 0;
		break;
	default:
		assert(0);
	}

	sqe = io_uring_get_sqe(conn->ring);
	if (!sqe) {
		perror("io_uring_get_sqe");
		return;
	}

	io_uring_prep_shutdown(sqe, conn->sock, how);
	io_uring_sqe_set_data(sqe, &conn->shutdown_op);
	submit_cancellable_op(conn->ring, &conn->shutdown_op);

	tunnel_session_ref(tunnel);
}

struct tunnel_session *tunnel_session_new(struct handshake_session *hs)
{
	struct tunnel_session *tunnel = NULL;

	struct io_uring *ring = NULL;

	struct circ_buf *client_read_buf = NULL;
	struct circ_buf *remote_read_buf = NULL;

	int client_sock = -1;
	int remote_sock = -1;

	assert(hs);
	assert(hs->remote);
	assert(hs->sock > 0);
	assert(hs->remote->sock > 0);

	ring = hs->ring;

	client_sock = hs->sock;
	hs->sock = -1;

	remote_sock = hs->remote->sock;
	hs->remote->sock = -1;

	client_read_buf = hs->read_buf;
	hs->read_buf = NULL;

	remote_read_buf = hs->write_buf;
	hs->write_buf = NULL;

	assert(circ_buf_empty(remote_read_buf));
	remote_read_buf->head = remote_read_buf->tail = 0;

	tunnel = calloc(1, sizeof(*tunnel));
	if (!tunnel)
		goto err_free_remote_buf;

	tunnel->ring = ring;

	tunnel->client_read_buf = client_read_buf;
	tunnel->remote_read_buf = remote_read_buf;

	tunnel->ref = 1;

	tunnel_connection_init(&tunnel->client, tunnel, &tunnel->remote,
			       client_sock, client_read_buf, remote_read_buf);
	tunnel_connection_init(&tunnel->remote, tunnel, &tunnel->client,
			       remote_sock, remote_read_buf, client_read_buf);

	tunnel->client.is_client = 1;
	tunnel->remote.is_client = 0;

	fprintf(stderr, "tunnel new: %p\n", (void *)tunnel);

	return tunnel;

err_free_remote_buf:
	free(remote_read_buf);

	close(client_sock);
	close(remote_sock);
	free(client_read_buf);

	fprintf(stderr, "tunnel new error\n");
	errno = ENOMEM;
	return NULL;
}

void tunnel_start(struct tunnel_session *ses)
{
	if (!circ_buf_empty(ses->client_read_buf))
		tunnel_do_write(&ses->remote);

	if (circ_buf_space(ses->client_read_buf) != 0)
		tunnel_do_read(&ses->client);

	if (circ_buf_space(ses->remote_read_buf) != 0)
		tunnel_do_read(&ses->remote);

	tunnel_session_unref(ses);
}

void tunnel_connection_init(struct tunnel_connection *conn,
			    struct tunnel_session *owner,
			    struct tunnel_connection *other, int sock,
			    struct circ_buf *read_buf,
			    struct circ_buf *write_buf)
{
	conn->owner = owner;
	conn->ring = owner->ring;
	conn->other = other;
	conn->sock = sock;
	conn->read_buf = read_buf;
	conn->write_buf = write_buf;

	conn->read_op.op_data.callback = tunnel_read_callback;
	conn->write_op.op_data.callback = tunnel_write_callback;
	conn->shutdown_op.callback = tunnel_shutdown_callback;

	conn->readable = 1;
	conn->writable = 1;
}

static void tunnel_connection_exit(struct tunnel_connection *conn)
{
	close(conn->sock);
}

static void create_listeners(struct io_uring *ring, const char *host,
			     const char *service)
{
	int s;
	struct addrinfo hint, *ai = NULL, *iter;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;

	for (;;) {
		s = getaddrinfo(host, service, &hint, &ai);
		if (s == 0)
			break;

		if (s == EAI_AGAIN)
			continue;

		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	for (iter = ai; iter != NULL; iter = iter->ai_next) {
		struct listener *l =
			listener_new(ring, iter->ai_addr, iter->ai_addrlen);
		if (l) {
			listener_do_accept(l);
			listener_unref(l);
		}
	}

	freeaddrinfo(ai);
}

struct signalfd_data {
	struct op_data op_data;
	struct io_uring *ring;
	struct signalfd_siginfo siginfo;
	int sfd;
	bool signaled;
};

static int signalfd_do_read(struct signalfd_data *sigdata);

static void signalfd_read_callback(void *data, int res, unsigned flags)
{
	struct signalfd_data *sigdata = data;
	(void)flags;

	trace_callback();

	if (res == -ECANCELED || res == -EINTR)
		return;

	if (res < 0)
		err_exit_n(-res, "signalfd read");

	if (sigdata->siginfo.ssi_signo != SIGPIPE)
		sigdata->signaled = true;

	signalfd_do_read(sigdata);
}

static int signalfd_data_init(struct signalfd_data *sigdata,
			      struct io_uring *ring)
{
	sigset_t mask;

	if (sigemptyset(&mask) < 0)
		return -errno;
	if (sigaddset(&mask, SIGINT) < 0)
		return -errno;
	if (sigaddset(&mask, SIGTERM) < 0)
		return -errno;
	if (sigaddset(&mask, SIGHUP) < 0)
		return -errno;
	if (sigaddset(&mask, SIGPIPE) < 0)
		return -errno;

	sigdata->ring = ring;
	sigdata->op_data.callback = signalfd_read_callback;
	sigdata->sfd = signalfd(-1, &mask, 0);
	if (sigdata->sfd < 0)
		return -errno;
	sigdata->signaled = false;
	memset(&sigdata->siginfo, 0, sizeof(sigdata->siginfo));

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		int errsv = errno;
		close(sigdata->sfd);
		return -errsv;
	}
	return 0;
}

static int signalfd_do_read(struct signalfd_data *sigdata)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(sigdata->ring);
	if (!sqe)
		return -EBUSY;
	io_uring_prep_read(sqe, sigdata->sfd, &sigdata->siginfo,
			   sizeof(sigdata->siginfo), 0);
	io_uring_sqe_set_data(sqe, sigdata);
	submit_cancellable_op(sigdata->ring, &sigdata->op_data);
	return 0;
}

static void cancel_callback(void *data, int res, unsigned flags)
{
	(void)data;
	(void)res;
	(void)flags;

	trace_callback();
}

static void complete_cqe(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	int res = cqe->res;
	unsigned flags = cqe->flags;
	struct op_data *op = io_uring_cqe_get_data(cqe);
	io_uring_cqe_seen(ring, cqe);
	list_del_init(&op->list);
	op->callback(op, res, flags);
}

static void cancel_submitted_ops(struct io_uring *ring)
{
	int s;
	struct op_data *op, *tmp;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct op_data cancel_op;

	cancel_op.callback = cancel_callback;
	INIT_LIST_HEAD(&cancel_op.list);

	trace_function();

	while (!list_empty(&submitted_ops)) {
		list_for_each_entry_safe (op, tmp, &submitted_ops, list) {
			sqe = io_uring_get_sqe(ring);
			if (!sqe)
				break;

			io_uring_prep_cancel(sqe, op, 0);
			io_uring_sqe_set_data(sqe, &cancel_op);
		}

		s = io_uring_submit_and_wait(ring, 1);
		if (s < 0 && s != -EINTR)
			err_exit_n(-s, "io_uring_submit_and_wait");

		while ((s = io_uring_peek_cqe(ring, &cqe)) == 0) {
			if (!cqe)
				break;
			complete_cqe(ring, cqe);
		}
	}
}

int main(int argc, char **argv)
{
	struct io_uring ring;
	struct signalfd_data sigdata;
	int s;

	if (argc != 3) {
		fprintf(stderr, "usage: %s host service\n", argv[0]);
		return 1;
	}

	s = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
	if (s < 0) {
		err_exit_n(-s, "io_uring_queue_init");
	}

	s = signalfd_data_init(&sigdata, &ring);
	if (s != 0) {
		io_uring_queue_exit(&ring);
		err_exit_n(-s, "signalfd_data_init");
	}

	s = signalfd_do_read(&sigdata);
	if (s != 0) {
		close(sigdata.sfd);
		io_uring_queue_exit(&ring);
		err_exit_n(-s, "signalfd_do_read");
	}

	create_listeners(&ring, argv[1], argv[2]);

	while (!sigdata.signaled) {
		struct io_uring_cqe *cqe = NULL;
		if ((s = io_uring_wait_cqe(&ring, &cqe)) < 0) {
			if (s == EINTR)
				continue;
			else
				break;
		}

		do {
			if (!cqe)
				break;
			complete_cqe(&ring, cqe);
		} while ((s = io_uring_peek_cqe(&ring, &cqe)) != 0);
	}

	cancel_submitted_ops(&ring);
	io_uring_queue_exit(&ring);
}

/*	$Id$	*/

/*-
 * Copyright (c)2004 YAMAMOTO Takashi,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <err.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct args {
	int fd;
	SSL *ssl;
};

void ssl_err(SSL *, int, const char *);
void *sslreader(void *);
void *sslwriter(void *);
int s_connect(const char *, const char *);
int main(int, char *[]);

void
ssl_err(SSL *ssl, int ret, const char *msg)
{
	char buf[120];
	unsigned long e;
	int sslerror = SSL_ERROR_SYSCALL;

	if (ssl) {
		sslerror = SSL_get_error(ssl, ret);
	}

	e = ERR_get_error();
	if (sslerror == SSL_ERROR_SYSCALL && e == 0) {
		perror(msg);
	} else {
		SSL_load_error_strings();
		ERR_error_string(e, buf);
		fprintf(stderr, "%s: %s\n", msg, buf);
	}

	exit(EXIT_FAILURE);
}

void *
sslreader(void *vp)
{
	struct args *args = vp;
	int fd = args->fd;
	SSL *ssl = args->ssl;

	while (/* CONSTCOND */ 1) {
		ssize_t n;
		int ret;
		char buf[4096*16];
		int error;

		ret = SSL_read(ssl, buf, sizeof(buf));
		switch (error = SSL_get_error(ssl, ret)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_ZERO_RETURN:
			break;
		case SSL_ERROR_SYSCALL:
			if (ret != 0) {
				err(EXIT_FAILURE, "read");
			}
			break;
		default:
/*			fprintf(stderr, "SSL_read %d, %d\n", ret, error); */
			ssl_err(ssl, error, "read");
		}
		n = ret;
		if (n == 0) {
			break;
		}
		while (n > 0) {
			ssize_t written;

			written = write(fd, buf, (size_t)n);
			if (written == (ssize_t)-1) {
				err(EXIT_FAILURE, "write");
			}
			if (written == 0) {
				break;
			}
			n -= written;
		}
	}

	shutdown(fd, SHUT_WR);

	return 0;
}

void *
sslwriter(void *vp)
{
	struct args *args = vp;
	int fd = args->fd;
	SSL *ssl = args->ssl;

	while (/* CONSTCOND */ 1) {
		ssize_t n;
		char buf[4096*16];

		n = read(fd, buf, sizeof(buf));
		if (n == (ssize_t)-1) {
			err(EXIT_FAILURE, "read");
		}
		if (n == 0) {
			break;
		}
		while (n > 0) {
			int ret;

			ret = SSL_write(ssl, buf, n);
			switch (SSL_get_error(ssl, ret)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_ZERO_RETURN:
				break;
			default:
				ssl_err(ssl, ret, "write");
			}
			n -= ret;
		}
	}

	shutdown(fd, SHUT_RD);

	return 0;
}

int
s_connect(const char *target, const char *port)
{
	struct addrinfo hint, *res0, *res;
	int s = -1;
	int error;

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = SOCK_STREAM;
/*	hint.ai_socktype = SOCK_DGRAM; */

	error = getaddrinfo(target, port, &hint, &res0);
	if (error) {
		errx(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(error));
	}
	if (res0->ai_canonname) {
		printf("canonname: %s\n", res0->ai_canonname);
	}
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			perror("socket");
			continue;
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			perror("connect");
			close(s);
			s = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(res0);

	return s;
}

int
main(int argc, char *argv[])
{
	char *target;
	char *port;
	int s;
	SSL_CTX *ctx;
	SSL *ssl;
	int rv;
	pthread_t reader;
	struct args readerargs;
	pthread_t writer;
	struct args writerargs;

	SSL_library_init();
	ctx = SSL_CTX_new(SSLv3_client_method());
	if (ctx == NULL) {
		ssl_err(NULL, 0, "SSL_CTX_new");
	}

	if (argc != 3) {
		errx(EXIT_FAILURE, "arg");
	}
	target = argv[1];
	port = argv[2];

	s = s_connect(target, port);
	if (s < 0) {
		errx(EXIT_FAILURE, "no connectable address");
	}
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		ssl_err(NULL, 0, "SSL_new");
	}
	rv = SSL_set_fd(ssl, s);
	if (!rv) {
		ssl_err(ssl, rv, "SSL_set_fd");
	}
	rv = SSL_connect(ssl);
	if (rv <= 0) {
		ssl_err(ssl, rv, "SSL_connect");
	}

	readerargs.fd = STDOUT_FILENO;
	readerargs.ssl = ssl;
	if (pthread_create(&reader, NULL, sslreader, &readerargs)) {
		err(EXIT_FAILURE, "pthread_create");
	}

	writerargs.fd = STDIN_FILENO;
	writerargs.ssl = ssl;
	if (pthread_create(&writer, NULL, sslwriter, &writerargs)) {
		err(EXIT_FAILURE, "pthread_create");
	}

	if (pthread_join(reader, NULL)) {
		err(EXIT_FAILURE, "pthread_join");
	}

	if (pthread_join(writer, NULL)) {
		err(EXIT_FAILURE, "pthread_join");
	}

	if (close(s)) {
		err(EXIT_FAILURE, "close");
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	exit(EXIT_SUCCESS);
	/* NOTREACHED */
}

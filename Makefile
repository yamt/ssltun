# $Id$

PROG=	ssltun
SRCS=	ssltun.c
NOMAN=

WARNS?=	4

LDADD+=	-lcrypto -lssl -lpthread
DPADD+= ${LIBCRYPTO} ${LIBSSL} ${LIBPTHREAD}

.include <bsd.prog.mk>

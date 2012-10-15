#	$Id: Makefile,v 1.1.1.1 2012/03/16 14:13:08 raxis Exp $

PROG=	googleauth
SRCS=	googleauth.c base32.c 
CFLAGS+=-DPASSWD -Wall -std=c99 -ggdb -O0 
	
DPADD+= ${LIBUTIL}
LDADD+= -lutil -lcrypto

BINOWN=	root
BINGRP=	auth
BINMODE=2555
BINDIR=	/usr/bin

.include <bsd.prog.mk>

#	$Id: Makefile,v 1.1.1.1 2012/03/16 14:13:08 raxis Exp $
#The png package is requried to compile this program
PROG=	googleauth
SRCS=	googleauth.c base32.c 
CFLAGS+=-DPASSWD -Wall -std=c99 -ggdb -O0 -I/usr/local/include/libpng16 -I/usr/local/include
	
DPADD+= ${LIBUTIL}
LDADD+= -lutil -lcrypto -L/usr/local/lib -lpng

BINOWN=	root
BINGRP=	auth
BINMODE=2555
BINDIR=	/usr/bin

.include <bsd.prog.mk>

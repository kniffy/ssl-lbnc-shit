bin_PROGRAMS=ssl-lbnc

ssl_lbnc_SOURCES=lbnc.c listener.c client.c relay.c server.c data.c	\
                 ident.c client.h data.h ident.h lbnc.h listener.h	\
                 relay.h server.h version.h

ssl_lbnc_CFLAGS=-I$(top_srcdir)/lion/src
ssl_lbnc_LDADD=$(top_srcdir)/lion/src/liblion.a

# Win32 extras
EXTRA_DIST=getopt.c w32service.c

# Automatically increase build version if found.
all-local:
	@if test -n "$(BUILD)"; then "$(BUILD)" ; fi


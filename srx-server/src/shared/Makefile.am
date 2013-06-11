include $(top_srcdir)/Makefile_Common

EXTRA_DIST = 

COPTS = -ggdb -I$(EXTRAS_INCLUDE_DIR) -I$(top_srcdir)

lib_LTLIBRARIES = libsrx_packets.la
libsrx_packets_la_SOURCES = srx_packets.c \
			    srx_identifier.c \
			    crc32.c
			  
noinst_HEADERS =  srx_packets.h \
	    srx_defs.h \
		  srx_identifier.h \
		  rpki_router.h \
		  crc32.h

#libsrx_packets_la_CFLAGS = -fPIC
#noinst_LTLIBRARIES = libsrx_packets.la


#srx_packet_objdir=$(srcdir)
#dist_srx_packet_obj_DATA = $(srcdir)/.libs/srx_packets.o \
#			   $(srcdir)/srx_packets.o


#noinst_DATA = srx_packets.o 

srx_packets.o: srx_packets.c
	$(LIBTOOL) --mode=compile cc $(COPTS) -c $< -o $@

all-hook: FORCE

FORCE:
#	$(MAKE) clean;
#	$(MAKE) $(AM_MAKESET) $@
	
.PHONY: all FORCE

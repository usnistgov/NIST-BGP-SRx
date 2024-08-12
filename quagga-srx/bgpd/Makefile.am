## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib $(BGPD_INCLUDES)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600


if ENABLE_GRPC_COND
GRPC_SERVER_LIBS = -lsrx_grpc_server
GRPC_CLIENT_LIBS = -lsrx_grpc_client
GRPC_LIBS = $(GRPC_SERVER_LIBS) $(GRPC_CLIENT_LIBS)

GRPC_DIR = $(grpc_dir)
GRPC_SERVER_PATH = $(GRPC_DIR)/server
GRPC_CLIENT_PATH = $(GRPC_DIR)/client

GRPC_SERVER_LDFLAG = -L$(GRPC_SERVER_PATH) #-rpath '$(GRPC_SERVER_PATH)'
GRPC_CLIENT_LDFLAG = -L$(GRPC_CLIENT_PATH) #-rpath '$(GRPC_CLIENT_PATH)'

GRPC_SERVER_RPATH = -rpath '$(GRPC_SERVER_PATH)'
GRPC_CLIENT_RPATH = -Wl,-rpath -Wl,$(GRPC_CLIENT_PATH)
#GRPC_CLIENT_RPATH = -rpath '$(GRPC_CLIENT_PATH)'
GRPC_CFLAGS = -I$(GRPC_DIR)
endif



AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS) -ldl

noinst_LIBRARIES = libbgp.a
sbin_PROGRAMS = bgpd

libbgp_a_SOURCES = \
	bgpd.c bgp_fsm.c bgp_aspath.c bgp_community.c bgp_attr.c \
	bgp_debug.c bgp_route.c bgp_zebra.c bgp_open.c bgp_routemap.c \
	bgp_packet.c bgp_network.c bgp_filter.c bgp_regex.c bgp_clist.c \
	bgp_dump.c bgp_snmp.c bgp_ecommunity.c bgp_mplsvpn.c bgp_nexthop.c \
	bgp_damp.c bgp_table.c bgp_advertise.c bgp_vty.c bgp_mpath.c \
	bgp_info_hash.c bgp_validate.c

noinst_HEADERS = \
	bgp_aspath.h bgp_attr.h bgp_community.h bgp_debug.h bgp_fsm.h \
	bgp_network.h bgp_open.h bgp_packet.h bgp_regex.h bgp_route.h \
	bgpd.h bgp_filter.h bgp_clist.h bgp_dump.h bgp_zebra.h \
	bgp_ecommunity.h bgp_mplsvpn.h bgp_nexthop.h bgp_damp.h bgp_table.h \
	bgp_advertise.h bgp_snmp.h bgp_vty.h bgp_mpath.h bgp_info_hash.h \
	bgp_validate.h

bgpd_SOURCES = bgp_main.c

if ENABLE_GRPC_COND
bgpd_LDADD = libbgp.a ../lib/libzebra.la $(GRPC_CLIENT_LIBS) @LIBCAP@ @LIBM@
bgpd_LDFLAGS = $(GRPC_CLIENT_LDFLAG) $(GRPC_CLIENT_RPATH)
else
bgpd_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@
endif

examplesdir = $(exampledir)
dist_examples_DATA = bgpd.conf.sample bgpd.conf.sample2 bgpd.conf.sampleSRx

EXTRA_DIST = BGP4-MIB.txt


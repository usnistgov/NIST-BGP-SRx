ACLOCAL_AMFLAGS = -I m4

.PHONY: clean-local distclean-local install-exec-local uninstall-local \
	all-local rpmcheck srcrpm rpms set-revision \
	set-revision-1

# Directories containing source files.
CLIENT_DIR = client
SERVER_DIR = server
SHARED_DIR = shared
TOOLS_DIR = tools
UTIL_DIR = util

# Read the revision number of the revision file
# This needs GNU-Make. if this is a problem, replace the 
# assignment of SRX_REVISION=... with either an empty
# string or the content of the revision file.
SRX_REVISION=$(shell cat $(SRX_REVISION_FILE))

AM_CFLAGS = -DSRX_REVISION=$(SRX_REVISION) \
            -DSRX_SERVER_PACKAGE=$(PACKAGE_VERSION)

# Used to generate the srx folder for installation - DESTDIR for RPM generation
INC_OUT = $(DESTDIR)$(includedir)/$(SRX_DIR)
#INC_OUT = srx

EXTRA_DIST = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).spec \
             $(PACKAGE_TARNAME)-proxy-$(PACKAGE_VERSION).spec \
             $(CLIENT_DIR)/srxproxy$(CPU_ARCH).conf

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

# Temporary Libraries
noinst_LTLIBRARIES = libsrx_shared.la libsrx_util.la

libsrx_shared_la_SOURCES = \
	             $(SHARED_DIR)/srx_packets.c \
	             $(SHARED_DIR)/srx_identifier.c \
	             $(SHARED_DIR)/crc32.c
	
libsrx_util_la_SOURCES = \
	             $(UTIL_DIR)/client_socket.c \
		     $(UTIL_DIR)/debug.c \
		     $(UTIL_DIR)/directory.c \
		     $(UTIL_DIR)/log.c \
		     $(UTIL_DIR)/multi_client_socket.c \
		     $(UTIL_DIR)/mutex.c \
		     $(UTIL_DIR)/packet.c \
		     $(UTIL_DIR)/plugin.c \
		     $(UTIL_DIR)/prefix.c \
		     $(UTIL_DIR)/rwlock.c \
		     $(UTIL_DIR)/server_socket.c \
		     $(UTIL_DIR)/slist.c \
		     $(UTIL_DIR)/socket.c \
		     $(UTIL_DIR)/str.c \
		     $(UTIL_DIR)/timer.c \
		     $(UTIL_DIR)/xml_out.c

################################################################################
##  SRX - PROXY - API INSTALL
################################################################################

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else 
  LIB_VER = 0:0:0
endif

pkglib_LTLIBRARIES = libSRxProxy.la
pkglibdir = $(libdir)/$(SRX_DIR)
	
libSRxProxy_la_SOURCES = $(CLIENT_DIR)/client_connection_handler.c \
		    $(CLIENT_DIR)/srx_api.c

# General linker flags
libSRxProxy_la_LIBADD = libsrx_shared.la libsrx_util.la
libSRxProxy_la_LDFLAGS = -version-info $(LIB_VER)
libSRxProxy_libconfigdir = $(sysconfdir)/ld.so.conf.d
dist_libSRxProxy_libconfig_DATA = $(CLIENT_DIR)/srxproxy$(CPU_ARCH).conf

################################################################################
##  END SRX - PROXY - API INSTALL
################################################################################


################################################################################
##  SRX SERVER INSTALL
################################################################################
## srx-server
srxdir=$(bindir)

# srx Settigns
srx_PROGRAMS     = srx_server
srx_configdir    = $(sysconfdir)
srx_initddir     = $(sysconfdir)/rc.d/init.d

dist_srx_config_DATA    = $(SERVER_DIR)/srx_server.conf
dist_srx_initd_DATA     = $(SERVER_DIR)/srx_serverd

#bin_PROGRAMS = srx_server

srx_server_SOURCES = $(SERVER_DIR)/bgpsec_handler.c \
	     	     $(SERVER_DIR)/command_handler.c \
		     $(SERVER_DIR)/command_queue.c \
		     $(SERVER_DIR)/configuration.c \
		     $(SERVER_DIR)/console.c \
		     $(SERVER_DIR)/key_cache.c \
		     $(SERVER_DIR)/main.c \
		     $(SERVER_DIR)/prefix_cache.c \
		     $(SERVER_DIR)/rpki_handler.c \
		     $(SERVER_DIR)/rpki_router_client.c \
		     $(SERVER_DIR)/server_connection_handler.c \
		     $(SERVER_DIR)/srx_packet_sender.c \
		     $(SERVER_DIR)/update_cache.c 

srx_server_LDADD = $(LIB_PATRICIA) $(LIB_SCA) \
		   libsrx_shared.la \
		   libsrx_util.la
srx_server_LDFLAGS = $(LIB_SCA_LDFLAGS)

# For the revision
SRX_VENDOR=antd.nist.gov
SVN_DIR = .svn
SVN_CMD = /usr/bin/svn

################################################################################
##  END SRX SERVER INSTALL
################################################################################

################################################################################
##  SRX TOOLS
################################################################################
toolsdir=$(bindir)

tools_PROGRAMS= rpkirtr_client rpkirtr_svr srxsvr_client

# Will be bundled with srx
rpkirtr_client_SOURCES = $(TOOLS_DIR)/rpkirtr_client.c \
		         $(SERVER_DIR)/rpki_router_client.c
rpkirtr_client_LDADD   = libsrx_util.la

# Will be bundled with srx
rpkirtr_svr_SOURCES = $(TOOLS_DIR)/rpkirtr_svr.c 
rpkirtr_svr_LDADD   = libsrx_util.la

# Will be bundled with srx-proxy
srxsvr_client_SOURCES = $(TOOLS_DIR)/srxsvr_client.c 
srxsvr_client_LDADD   = libsrx_util.la libsrx_shared.la libSRxProxy.la


################################################################################
##  END SRX TOOLS
################################################################################

# Don't install
noinst_HEADERS = $(CLIENT_DIR)/client_connection_handler.h \
		 $(CLIENT_DIR)/srx_api.h \
		 \
		 $(SERVER_DIR)/bgpsec_handler.h \
		 $(SERVER_DIR)/command_handler.h \
		 $(SERVER_DIR)/command_queue.h \
		 $(SERVER_DIR)/configuration.h \
		 $(SERVER_DIR)/console.h \
		 $(SERVER_DIR)/key_cache.h \
		 $(SERVER_DIR)/prefix_cache.h \
		 $(SERVER_DIR)/rpki_handler.h \
		 $(SERVER_DIR)/rpki_router_client.h \
		 $(SERVER_DIR)/server_connection_handler.h \
		 $(SERVER_DIR)/srx_packet_sender.h \
		 $(SERVER_DIR)/srx_server.h \
		 $(SERVER_DIR)/update_cache.h \
		 \
		 $(SHARED_DIR)/srx_packets.h \
		 $(SHARED_DIR)/srx_defs.h \
		 $(SHARED_DIR)/srx_identifier.h \
		 $(SHARED_DIR)/rpki_router.h \
		 $(SHARED_DIR)/crc32.h \
		 \
		 $(UTIL_DIR)/client_socket.h \
		 $(UTIL_DIR)/debug.h \
		 $(UTIL_DIR)/directory.h \
		 $(UTIL_DIR)/log.h \
		 $(UTIL_DIR)/math.h \
		 $(UTIL_DIR)/multi_client_socket.h \
		 $(UTIL_DIR)/mutex.h \
		 $(UTIL_DIR)/packet.h \
		 $(UTIL_DIR)/plugin.h \
		 $(UTIL_DIR)/prefix.h \
		 $(UTIL_DIR)/rwlock.h \
		 $(UTIL_DIR)/server_socket.h \
		 $(UTIL_DIR)/slist.h \
		 $(UTIL_DIR)/socket.h \
		 $(UTIL_DIR)/str.h \
		 $(UTIL_DIR)/test.h \
		 $(UTIL_DIR)/timer.h \
		 $(UTIL_DIR)/xml_out.h

set-revision:
	@echo "Check for revision framework"
	@touch $(SRX_REVISION_FILE);
	@if test -d $(SVN_DIR); then \
	  if test -f $(SVN_CMD); then \
	    $(SVN_CMD) info | grep $(SRX_VENDOR); \
	    if test "$$?" = "0"; then \
	      $(SVN_CMD) info | grep $(SRX_VENDOR); \
	      if test "$$?" = "0"; then \
		$(MAKE) set-revision-1; \
	      fi; \
	    fi; \
	  fi; \
	fi;
	
set-revision-1:
	@echo "Revision file=" $(SRX_REVISION_FILE)
	@echo -n $$($(SVN_CMD) info | grep Revision | sed -e "s/\(Revision:[ ]*\)\(.*\)\([ ]*\)/R\2-/g") > $(SRX_REVISION_FILE)
	@echo -n $$($(SVN_CMD) info | grep "Last Changed Rev" | sed -e "s/\(Last Changed Rev:[ ]*\)\(.*\)\([ ]*\)/LR\2/g") >> $(SRX_REVISION_FILE)
	@echo -n "Full-Version = $(VERSION)-"
	@cat $(SRX_REVISION_FILE)
	@echo
	@echo
	
distclean-local:
	rm -f *.spec *.rpm $(CLIENT_DIR)/*.conf; \
	rm -rf autom4te.cache; 

install-exec-local:
	@if [ ! -d $(INC_OUT) ]; then \
	  mkdir -p $(INC_OUT); \
	fi
	@echo "Copying and modifing 'srx headers'";
	cat $(CLIENT_DIR)/srx_api.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <$(SRX_DIR)\2>/g' > $(INC_OUT)/srx_api.h
	cat $(SHARED_DIR)/srx_defs.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <$(SRX_DIR)\2>/g' > $(INC_OUT)/srx_defs.h
	cat $(UTIL_DIR)/prefix.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <$(SRX_DIR)\2>/g' > $(INC_OUT)/prefix.h
	cat $(UTIL_DIR)/slist.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <$(SRX_DIR)\2>/g' > $(INC_OUT)/slist.h
		
uninstall-local:
	rm -f $(INC_OUT)/srx_api.h \
	      $(INC_OUT)/srx_defs.h \
	      $(INC_OUT)/prefix.h \
	      $(INC_OUT)/slist.h;
	@if [ -e $(INC_OUT) && "$(ls -A $(INC_OUT))" == "" ] ; then \
	  rmdir $(INC_OUT) > /dev/null 2>&1; \
	fi
	
all-local: set-revision 
	chmod ugo+x $(SERVER_DIR)/srx_serverd > /dev/null 2>&1

################################################################################
##  RPM GENERATION
################################################################################

# RPM script and macros for SRx
rpm_spec = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).spec
rpm_proxy_spec = $(PACKAGE_TARNAME)-proxy-$(PACKAGE_VERSION).spec

rpmmacros =\
 --define="_rpmdir $${PWD}"\
 --define="_srcrpmdir $${PWD}"\
 --define="_sourcedir $${PWD}/../extras/files/"\
 --define="_specdir $${PWD}"\
 --define="_builddir $${PWD}"

RPMBUILD = rpmbuild
RPMFLAGS = --nodeps --buildroot="$${PWD}/_rpm"

rpmcheck:
	if [ which rpmbuild &> /dev/null ]; then \
	 echo "*** This make target requires an rpm-based linux distribution."; \
	(exit 1); exit 1; \
	fi

srcrpm: rpmcheck $(rpm_spec) $(rpm_proxy_spec)
	$(RPMBUILD) $(RPMFLAGS) -bs $(rpmmacros) $(rpm_spec)

rpms: rpmcheck $(rpm_spec) $(rpm_proxy_spec)
	$(RPMBUILD) $(RPMFLAGS) -ba $(rpmmacros) $(rpm_spec)
	$(RPMBUILD) $(RPMFLAGS) -bb $(rpmmacros) $(rpm_proxy_spec)

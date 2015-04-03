include $(top_srcdir)/Makefile_Common

EXTRA_DIST = $(top_srcdir)/server/srx_lib.conf \
	     $(top_srcdir)/server/srx_lib-x86_64.conf
	
lib_LTLIBRARIES = 

#LIBS = -lpthread -lconfig -lpatricia -lrt
LIBS = -lpthread -lconfig -lrt
L_FLAGS = -L$(EXTRAS_LIB) 

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

srxdir=$(bindir)
srx_PROGRAMS = srx_server
srx_server_LDFLAGS = $(L_FLAGS) $(LIBS)
srx_server_SOURCES = bgpsec_handler.c \
	     	     command_handler.c \
		     command_queue.c \
		     configuration.c \
		     console.c \
		     key_cache.c \
		     main.c \
		     prefix_cache.c \
		     rpki_handler.c \
		     rpki_router_client.c \
		     server_connection_handler.c \
		     srx_packet_sender.c \
		     update_cache.c 
srx_server_LDADD = $(top_srcdir)/shared/srx_packets.lo  \
		   $(top_srcdir)/shared/srx_identifier.lo \
		   $(top_srcdir)/shared/crc32.lo \
		   $(top_srcdir)/util/libsrxutil.la \
		   $(top_srcdir)/client/libsrx.la \
		   $(EXTRAS_DIR)/../libpatricia.a

# srx server configuration file setting
#srx_configdir = $(pkgdatadir)
srx_configdir = $(sysconfdir)
srx_libconfigdir = $(sysconfdir)/ld.so.conf.d
dist_srx_config_DATA = srx_server.conf
dist_srx_libconfig_DATA = srx_lib$(CPU_ARCH).conf

#srx_server_CPPFLAGS = -I$(EXTRAS_INCLUDE_DIR) -g

 noinst_HEADERS = bgpsec_handler.h \
		  command_handler.h \
		  command_queue.h \
		  configuration.h \
		  console.h \
		  key_cache.h \
		  prefix_cache.h \
		  rpki_handler.h \
		  rpki_router_client.h \
		  server_connection_handler.h \
		  srx_packet_sender.h \
		  srx_server.h \
		  update_cache.h \
		  $(top_srcdir)/shared/srx_packets.h \
		  $(EXTRAS_INCLUDE_DIR)/patricia.h \
		  $(EXTRAS_INCLUDE_DIR)/uthash.h

# following headers will be used for the quaggasrx rpm 
pkginclude_HEADERS = $(CLIENT_DIR)/$(PACKAGE)/uthash.h \
					 $(CLIENT_DIR)/$(PACKAGE)/types.h \
					 $(CLIENT_DIR)/$(PACKAGE)/srx_defs.h \
					 $(CLIENT_DIR)/$(PACKAGE)/srx_api.h \
					 $(CLIENT_DIR)/$(PACKAGE)/slist.h \
					 $(CLIENT_DIR)/$(PACKAGE)/prefix.h


tags-local:
	@ctags $(CTAGS_OPTS) *.h $(SHARED_DIR)/*.h $(UTIL_DIR)/*.h \
		$(EXTRAS_INCLUDE)/patricia.h $(EXTRAS_INCLUDE)/uthash.h

clean-local: 
	rm -f $(OBJECTS) $(OUTPUT)
	rm -rf $(CLEAN_SUBDIRS)


echo:
	@echo " CLIENT_DIR in Makefile_Common: $(CLIENT_DIR)"
	@echo " SRC_DIR: $(SRC_DIR)"
	@echo " srcdir: $(srcdir)  top_srcdir: $(top_srcdir) "
	@echo " prefix: $(prefix)  pwd : `pwd` "
	@echo " abs_srcdir: $(abs_srcdir) abs_top_srcdir: $(abs_top_srcdir)"

install-exec-hook:
	-chmod go+rw -R $(pkgincludedir)
	-chmod go+r -R $(pkglibdir)

uninstall-hook:
	@echo "------- uninstall all installation data -------"
	-rm -rf ${pkgdatadir} ${pkgincludedir} ${pkglibexecdir} ${pkglibdir}

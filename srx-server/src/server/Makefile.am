include $(top_srcdir)/Makefile_Common

EXTRA_DIST = 
lib_LTLIBRARIES = 

LIBS = -lpthread -lconfig -lpatricia -lrt
L_FLAGS = -L$(EXTRAS_LIB) 

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

srx_configdir = $(bindir)
dist_srx_config_DATA = srx_server.conf
		     
srx_server_LDADD = $(top_srcdir)/shared/srx_packets.lo  \
		   $(top_srcdir)/shared/srx_identifier.lo \
		   $(top_srcdir)/shared/crc32.lo \
		   $(top_srcdir)/util/libutil.la \
		   $(top_srcdir)/client/libsrx.la


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





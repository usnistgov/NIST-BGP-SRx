include $(top_srcdir)/Makefile_Common

EXTRA_DIST = 
lib_LTLIBRARIES = 

READLINE_COPTS = -lreadline -lncurses -L$(EXTRAS_LIB)

#toolsdir=`pwd`
toolsdir=$(bindir)
tools_PROGRAMS= rpkirtr_client rpkirtr_svr srxsvr_client
rpkirtr_client_SOURCES = rpkirtr_client.c \
		       $(SERVER_DIR)/rpki_router_client.c
rpkirtr_client_LDFLAGS = -lpthread
rpkirtr_client_LDADD   = $(LIB_UTIL)

rpkirtr_svr_SOURCES = rpkirtr_svr.c 
rpkirtr_svr_LDFLAGS = -lpthread $(READLINE_COPTS) 
rpkirtr_svr_LDADD   = $(LIB_UTIL)

srxsvr_client_SOURCES = srxsvr_client.c 
srxsvr_client_LDFLAGS = -lpthread -lrt $(READLINE_COPTS) 
srxsvr_client_LDADD   = $(SHARED_DIR)/srx_identifier.lo \
		       	$(SHARED_DIR)/crc32.lo \
		       	$(LIB_UTIL) \
			$(LIB_SRX)

tags-local:
	@ctags $(CTAGS_OPTS) $(SHARED_DIR)/*.h $(UTIL_DIR)/*.h

clean-local: 
	rm -f $(RPKIRTR_DUMP_OBJS) $(RPKIRTR_SVR_OBJS) $(BINARIES)
	rm -rf $(CLEAN_SUBDIRS)
	rm -f .rpkirtr_svr.history



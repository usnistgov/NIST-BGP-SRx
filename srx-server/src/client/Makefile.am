
include $(top_srcdir)/Makefile_Common

EXTRA_DIST = 
pkglib_LTLIBRARIES = libsrx.la
libsrx_la_SOURCES = client_connection_handler.c \
		    srx_api.c 
		    
libsrx_la_LIBADD = $(top_srcdir)/shared/srx_packets.lo \
		   $(top_srcdir)/shared/srx_identifier.lo \
		   $(top_srcdir)/shared/crc32.lo \
		   $(top_srcdir)/util/libsrxutil.la

noinst_HEADERS = client_connection_handler.h \
	     srx_api.h  \
		   $(top_srcdir)/shared/srx_defs.h \
		   $(top_srcdir)/util/prefix.h \
		   $(top_srcdir)/util/types.h


#nobase_include_HEADERS = $(srcdir)/srx/prefix.h \
			 $(srcdir)/srx/slist.h \
			 $(srcdir)/srx/srx_api.h \
			 $(srcdir)/srx/srx_defs.h \
			 $(srcdir)/srx/types.h 

#pkginclude_HEADERS = $(INC_OUT)/srx_api.h \
		     $(INC_OUT)/srx_defs.h \
		     $(INC_OUT)/prefix.h \
		     $(INC_OUT)/slist.h \
		     $(INC_OUT)/types.h



INC_OUT = srx
HEADER_FILES = \
        $(top_srcdir)/client/srx_api.h \
        $(top_srcdir)/shared/srx_defs.h \
        $(top_srcdir)/util/prefix.h \
        $(top_srcdir)/util/slist.h \
        $(top_srcdir)/util/types.h

tags-local:
	@ctags $(CTAGS_OPTS) *.h $(SHARED_DIR)/*.h $(UTIL_DIR)/*.h

clean-local: 
	rm -f $(LOBJECTS) $(OUTPUT) $(OBJECTS)
	rm -rf $(CLEAN_SUBDIRS)
	rm -rf $(INC_OUT)

includes:
	@if [ ! -d $(INC_OUT) ]; then \
		mkdir $(INC_OUT); \
	fi
	echo Copying and modifing 'srx headers'; \
	perl -n -e 's/(\#include\s+")[a-z]+/\1srx/; print $$_;' < $(top_srcdir)/client/srx_api.h > $(INC_OUT)/srx_api.h; \
	perl -n -e 's/(\#include\s+")[a-z]+/\1srx/; print $$_;' < $(top_srcdir)/shared/srx_defs.h > $(INC_OUT)/srx_defs.h; \
	perl -n -e 's/(\#include\s+")[a-z]+/\1srx/; print $$_;' < $(top_srcdir)/util/prefix.h > $(INC_OUT)/prefix.h; \
	perl -n -e 's/(\#include\s+")[a-z]+/\1srx/; print $$_;' < $(top_srcdir)/util/slist.h > $(INC_OUT)/slist.h; \
	perl -n -e 's/(\#include\s+")[a-z]+/\1srx/; print $$_;' < $(top_srcdir)/util/types.h > $(INC_OUT)/types.h; 
	-cp $(EXTRAS_INCLUDE_DIR)/uthash.h $(INC_OUT) 

all-local: includes
	@echo "for makeing all-local"
	@ar cru libsrx.a .libs/srx_api.o .libs/client_connection_handler.o ../shared/.libs/srx_packets.o ../shared/.libs/srx_identifier.o ../shared/.libs/crc32.o ../util/.libs/socket.o ../util/.libs/client_socket.o ../util/.libs/packet.o ../util/.libs/rwlock.o ../util/.libs/log.o ../util/.libs/directory.o ../util/.libs/mutex.o ../util/.libs/server_socket.o ../util/.libs/plugin.o ../util/.libs/debug.o ../util/.libs/str.o ../util/.libs/slist.o ../util/.libs/timer.o ../util/.libs/prefix.o ../util/.libs/multi_client_socket.o ../util/.libs/xml_out.o 
	@mv libsrx.a ./srx
	@echo "------- update client/srx/headers and library ------"
	-@if [ ! -d $(pkgincludedir) ]; then \
	    mkdir -p $(pkgincludedir); \
	fi
	-cp -rf $(INC_OUT)/* $(pkgincludedir)

install-exec-hook: 
	@echo "------- Later MOVE client/srx to quaagga/srx -------"
	-cp -rf $(INC_OUT)/* $(pkgincludedir)

uninstall-hook:
	@echo "------- uninstall user data -------"
	-rm -rf $(pkgincludedir)


.PHONY: all includes


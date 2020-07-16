ACLOCAL_AMFLAGS = -I m4

CLEAN_SUBDIRS   = .libs .deps

lib_LTLIBRARIES = libantd_util.la
libantd_util_la_SOURCES = log.c         \
                          prefix.c      \
                          linked_list.c \
                          stack.c       \
                          printer.c     
#                          prefix_trie.c

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else
  LIB_VER = 0:0:0
endif

libantd_util_la_LDFLAGS = -version-info $(LIB_VER)

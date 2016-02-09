
ACLOCAL_AMFLAGS = -I m4

CLEAN_SUBDIRS	= .libs .deps

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else
  LIB_VER = 0:0:0
endif

lib_LTLIBRARIES = libSRxCryptoTestlib.la

#dist_SRxCryptoTestlib_libdir  = $(prefix_exec)/lib$(CPU_ARCH)/$(SRX_DIR)

libSRxCryptoTestlib_la_SOURCES = crypto_testlib.c
libSRxCryptoTestlib_la_LDFLAGS = -version-info $(LIB_VER)

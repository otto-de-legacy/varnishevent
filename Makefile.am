#

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

dist_man_MANS = varnishevent.1

varnishevent.1: README.rst
if HAVE_RST2MAN
	${RST2MAN} $? $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif

EXTRA_DIST = LICENSE autogen.sh README.rst

DISTCHECK_CONFIGURE_FLAGS = \
    --enable-developer-warnings \
    --enable-debugging-symbols \
    --enable-dependency-tracking \
    --enable-extra-developer-warnings \
    --enable-werror

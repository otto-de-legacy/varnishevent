#

INCLUDES = -I${VARNISH_SHARE_INCLUDE} -I${VARNISH_PKG_INCLUDE}

SUBDIRS = test

bin_PROGRAMS = varnishevent

dist_man_MANS = varnishevent.1

varnishevent_SOURCES = \
	varnishevent.c \
	varnishevent.h \
	signals.h \
	base64.c \
	base64.h \
	data.c \
	spscq.c \
	writer.c \
	config.c \
	log.c \
	monitor.c \
	strfTIM.h \
	strfTIM.c \
	format.c

#	handler.c

varnishevent_LDADD = \
	${PTHREAD_LIBS} ${RT_LIBS} ${LIBM} @VARNISH_LIBS@ \
	-L${VARNISH_PKG_LIB}/varnish -lvarnish

varnishevent.1: $(top_srcdir)/doc/varnishevent.rst
if HAVE_RST2MAN
	${RST2MAN} $? $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif

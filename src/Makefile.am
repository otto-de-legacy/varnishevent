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
	writer.h \
	writer.c \
	config.c \
	log.c \
	monitor.c \
	strfTIM.h \
	strfTIM.c \
	format.c \
	handler.c \
	vtim.h \
	vtim.c \
	vpf.h \
	vpf.c \
	flopen.h \
	flopen.c \
	vcs_version.h

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

# from Varnish include/Makefile.am
BUILT_SOURCES = vcs_version.h
MAINTAINERCLEANFILES = vcs_version.h 
vcs_version.h: FORCE
	@if [ -d "$(top_srcdir)/.git" ]; then \
		V="$$(git show -s --pretty=format:%h)" \
		B="$$(git rev-parse --abbrev-ref HEAD)" \
		H="$$(head -n 1 vcs_version.h 2>/dev/null || true)"; \
		if [ "/* $$V */" != "$$H" ]; then \
		( \
		  echo "/* $$V */" ;\
		  echo '/*' ;\
		  echo ' * NB:  This file is machine generated, DO NOT EDIT!' ;\
		  echo ' *' ;\
		  echo ' * Run make to regenerate' ;\
		  echo ' *'  ;\
		  echo ' */' ;\
		  echo "/* $$V */" ;\
		  echo '' ;\
		  echo "#define VCS_Version \"$$V\"" ; \
		  echo "#define VCS_Branch \"$$B\"" \
		) > vcs_version.h ; \
		fi \
	else \
		if [ ! -f vcs_version.h ]; then \
		( \
		  echo "/* NOGIT */" ; \
		  echo '/* No git commit ID available, see include/Makefile.am for explanation */' ; \
		  echo '#define VCS_Version "NOGIT"' ; \
		  echo '#define VCS_Branch "NOGIT"' \
		) >  vcs_version.h ; \
		fi \
	fi
FORCE:

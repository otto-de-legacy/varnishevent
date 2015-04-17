AM_CPPFLAGS = @VARNISH_CFLAGS@ -I ${ac_varnish_pkgdataincludedir}

TESTS = test_data test_strfTIM test_format test_writer ncsa.sh regress.sh # vslarg.sh

check_PROGRAMS = test_data test_strfTIM test_format test_writer

test_data_SOURCES = \
	minunit.h \
	test_data.c

test_data_LDADD = \
	../base64.$(OBJEXT) \
	../config.$(OBJEXT) \
	../log.$(OBJEXT) \
	../data.$(OBJEXT) \
	../format.$(OBJEXT) \
	../strfTIM.$(OBJEXT) \
	@VARNISH_LIBS@ @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

test_format_SOURCES = \
	minunit.h \
	test_format.c

test_format_LDADD = \
	../config.$(OBJEXT) \
	../strfTIM.$(OBJEXT) \
	../base64.$(OBJEXT) \
	../format.$(OBJEXT) \
	@VARNISH_LIBS@ @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

test_writer_SOURCES = \
	minunit.h \
	test_writer.c

test_writer_LDADD = \
	../config.$(OBJEXT) \
	../format.$(OBJEXT) \
	../log.$(OBJEXT) \
	../data.$(OBJEXT) \
	../monitor.$(OBJEXT) \
	../base64.$(OBJEXT) \
	../spscq.$(OBJEXT) \
	../strfTIM.$(OBJEXT) \
	../writer.$(OBJEXT) \
	@VARNISH_LIBS@ @VARNISH_LIBVARNISH_LIB@ -lvarnish

test_strfTIM_SOURCES = \
	minunit.h \
	../strfTIM.h \
	test_strfTIM.c

test_strfTIM_LDADD = \
	../strfTIM.$(OBJEXT) \
	@VARNISH_LIBS@  @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

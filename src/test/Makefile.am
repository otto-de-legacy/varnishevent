AM_CPPFLAGS = @VARNISH_CFLAGS@ -I ${ac_varnish_pkgdataincludedir}

TESTS = test_data test_strfTIM test_format # test_writer regress.sh ncsa.sh vslarg.sh

check_PROGRAMS = test_data test_strfTIM test_format # test_writer

test_data_SOURCES = \
	minunit.h \
	test_data.c

test_data_LDADD = \
	../base64.$(OBJEXT) \
	../config.$(OBJEXT) \
	../log.$(OBJEXT) \
	../data.$(OBJEXT) \
	@VARNISH_LIBS@ @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

test_format_SOURCES = \
	minunit.h \
	test_format.c

test_format_LDADD = \
	../config.$(OBJEXT) \
	../format.$(OBJEXT) \
	@VARNISH_LIBS@ @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

test_writer_SOURCES = \
	minunit.h \
	../writer.c

test_writer_LDADD = \
	../format.$(OBJEXT) \
	../log.$(OBJEXT) \
	../data.$(OBJEXT) \
	../monitor.$(OBJEXT) \
	../base64.$(OBJEXT) \
	../spscq.$(OBJEXT) \
	@VARNISH_LIBS@ -lvarnish

test_writer_CFLAGS = -DTEST_DRIVER

test_strfTIM_SOURCES = \
	minunit.h \
	../strfTIM.h \
	test_strfTIM.c

test_strfTIM_LDADD = \
	../strfTIM.$(OBJEXT) \
	@VARNISH_LIBS@  @VARNISH_LIBVARNISH_LIB@ -lm -lvarnish

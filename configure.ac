AC_PREREQ(2.59)
AC_COPYRIGHT([Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung
Copyright (c) 2015 Otto Gmbh & Co KG])
AC_INIT([varnishevent], [4.1.0])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(src/varnishevent.h)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_ARG_WITH([rst2man],
               AS_HELP_STRING([--with-rst2man=PATH],
                              [Location of rst2man (auto)]),
               [RST2MAN="$withval"],
               [AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], "no")
	        if test "x$RST2MAN" = "xno"; then
		   AC_MSG_WARN([rst2man not found – not building man pages])
		fi])
AM_CONDITIONAL(HAVE_RST2MAN,[test "x$RST2MAN" != "xno"])

AC_ARG_WITH([rst2html],
               AS_HELP_STRING([--with-rst2html=PATH],
                              [Location of rst2html (auto)]),
               [RST2HTML="$withval"],
               [AC_CHECK_PROGS(RST2HTML, [rst2html rst2html.py], "no")
	        if test "x$RST2HTML" = "xno"; then
		   AC_MSG_WARN([rst2html not found – not building changelog])
		fi])
AM_CONDITIONAL(HAVE_RST2HTML,[test "x$RST2HTML" != "xno"])

# Check for pkg-config
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([VARNISH], [varnishapi >= 4.0.3], [],
                  [AC_MSG_ERROR([Varnish >= 4.0.3 installation is required])])
AC_SUBST(VARNISH_CFLAGS)
AC_SUBST(VARNISH_LIBS)
PKG_CHECK_VAR([VARNISH_PKG_INCLUDE], [varnishapi], [pkgincludedir])
AC_SUBST(VARNISH_SHARE_INCLUDE, "${VARNISH_PKG_INCLUDE}/include")
PKG_CHECK_VAR(VARNISH_PKG_LIB, [varnishapi], [libdir])
AC_SUBST(VARNISH_LIBVARNISH_LIB, "-L${VARNISH_PKG_LIB}/varnish")

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/stdlib.h])

# Checks for libraries.
save_LIBS="${LIBS}"
LIBS=""
AC_CHECK_LIB(rt, clock_gettime)
RT_LIBS="${LIBS}"
LIBS="${save_LIBS}"
AC_SUBST(RT_LIBS)

save_LIBS="${LIBS}"
LIBS=""
AC_SEARCH_LIBS(pthread_create, [thr pthread c_r])
PTHREAD_LIBS="${LIBS}"
LIBS="${save_LIBS}"
AC_SUBST(PTHREAD_LIBS)

AC_CHECK_LIBM
AC_SUBST(LIBM)

m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([pkg.m4 missing, please install pkg-config])])
PKG_PROG_PKG_CONFIG

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_HEADERS([pthread_np.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([strerror])
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([strptime])
AC_CHECK_FUNCS([timegm])
AC_CHECK_FUNCS([nanosleep])
AC_CHECK_FUNCS([getline])
AC_CHECK_FUNCS([pthread_setname_np])

save_LIBS="${LIBS}"
LIBS="${PTHREAD_LIBS}"
AC_CHECK_FUNCS([pthread_set_name_np])
LIBS="${save_LIBS}"

# Use jemalloc on Linux
JEMALLOC_SUBDIR=
JEMALLOC_LDADD=
AC_ARG_WITH([jemalloc],
            [AS_HELP_STRING([--with-jemalloc],
              [use jemalloc memory allocator.  Default is yes on Linux,  no elsewhere])],
            [],
            [with_jemalloc=check])

case $target in
    *-*-linux*)
        if test "x$with_jemalloc" != xno; then
            AC_CHECK_LIB([jemalloc], [malloc_conf],
                  [JEMALLOC_LDADD="-ljemalloc"],
                  [AC_MSG_NOTICE([No system jemalloc found, using bundled version])
                   JEMALLOC_SUBDIR=libjemalloc
                   JEMALLOC_LDADD='$(top_builddir)/lib/libjemalloc/libjemalloc_mt.la'])
	fi
	;;
esac
AC_SUBST(JEMALLOC_SUBDIR)
AC_SUBST(JEMALLOC_LDADD)

AC_CHECK_FUNCS([backtrace])
# white lie - we don't actually test it
AC_MSG_CHECKING([whether daemon() works])
case $target in
*-*-darwin*)
	# present but not functional
	AC_MSG_RESULT([no])
	ac_cv_func_daemon=no
	;;
*)
	AC_CHECK_FUNCS([daemon])
	;;
esac

AC_SYS_LARGEFILE

save_LIBS="${LIBS}"
LIBS="${LIBS} ${RT_LIBS}"
AC_CHECK_FUNCS([clock_gettime])
AC_CHECK_FUNCS([gethrtime]) 
LIBS="${save_LIBS}"

AC_CHECK_PROGS(PYTHON, [python3 python3.1 python3.2 python2.7 python2.6 python2.5 python2 python], "no")
if test "x$PYTHON" = "xno"; then
  AC_MSG_ERROR([Python is needed to build Varnish, please install python.])
fi

# Now that we're done using the compiler to look for functions and
# libraries, set CFLAGS to what we want them to be for our own code

# This corresponds to FreeBSD's WARNS level 6
DEVELOPER_CFLAGS_NOINLINE="-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts -Wnested-externs -Wredundant-decls -Wformat"
DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS_NOINLINE} -Winline"

# Additional flags for GCC 4
EXTRA_DEVELOPER_CFLAGS="-Wextra -Wno-missing-field-initializers -Wno-sign-compare"

# AC_PROG_CC sets CFLAGS to '-g -O2' unless it is already set, so
# there's no need to add -g. Disable or change by explicitly setting
# CFLAGS. If this option is enabled, then -Og or -O0 becomes the last
# optimization option, and hence takes precedence.
if test "x$enable_debugging" != "xno"; then
        CFLAGS="${CFLAGS} -fno-inline"
        DEVELOPER_CFLAGS=${DEVELOPER_CFLAGS_NOINLINE}
        AX_CHECK_COMPILE_FLAG([-Og],
                [CFLAGS="${CFLAGS} -Og"],
                [CFLAGS="${CFLAGS} -O0"],
                [])
fi

# --enable-developer-warnings
AC_ARG_ENABLE(developer-warnings,
	AS_HELP_STRING([--enable-developer-warnings],[enable strict warnings (default is NO)]),
	CFLAGS="${CFLAGS} ${DEVELOPER_CFLAGS}")

# --enable-debugging-symbols
AC_ARG_ENABLE(debugging-symbols,
	AS_HELP_STRING([--enable-debugging-symbols],[enable debugging symbols (default is NO)]),
	CFLAGS="${CFLAGS} -g")

# --enable-debugging
AC_ARG_ENABLE(debugging,
        AS_HELP_STRING([--enable-debugging],[enable debugging (default is NO)]),
        [],
        [enable_debugging=no])

# --enable-extra-developer-warnings
AC_ARG_ENABLE(extra-developer-warnings,
	AS_HELP_STRING([--enable-extra-developer-warnings],[enable even stricter warnings (default is NO)]),
	[],
	[enable_extra_developer_warnings=no])

if test "x$enable_stack_protector" != "xno"; then
	save_CFLAGS="$CFLAGS"
	CFLAGS="${CFLAGS} ${EXTRA_DEVELOPER_CFLAGS}"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([],[],[])],
		[],
		[AC_MSG_WARN([All of ${EXTRA_DEVELOPER_CFLAGS} not supported, disabling])
		    CFLAGS="$save_CFLAGS"])
fi

# --enable-stack-protector
AC_ARG_ENABLE(stack-protector,
	AS_HELP_STRING([--enable-stack-protector],[enable stack protector (default is NO)]),
	[],
	[enable_stack_protector=no])

if test "x$enable_stack_protector" != "xno"; then
	save_CFLAGS="$CFLAGS"
	CFLAGS="${CFLAGS} -fstack-protector-all"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([],[],[])],
		[],
		[AC_MSG_WARN([-fstack-protector not supported, disabling])
		    CFLAGS="$save_CFLAGS"])
fi

# --enable-werror
AC_ARG_ENABLE(werror,
	AS_HELP_STRING([--enable-werror],[use -Werror (default is NO)]),
	CFLAGS="${CFLAGS} -Werror")

# Generate output
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/test/Makefile
])
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libvdeplug_slirp], [0.2], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([libvdeplug_slirp.c])
AC_CONFIG_HEADERS([config.h])
AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC

LT_INIT

# Checks for libraries.
AC_CHECK_LIB([vdeplug], [vde_open_real])
AC_CHECK_LIB([vdeplug_mod], [vde_parseparms])
AC_CHECK_LIB([slirp], [slirp_open])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h stdlib.h string.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT


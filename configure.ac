#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(pam_externalpass, 0.11, thomas@habets.pp.se)
AC_CONFIG_SRCDIR([pam_externalpass.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([pam], [pam_get_item], , [AC_MSG_ERROR([libpam not found])])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdlib.h string.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 memset strdup strerror])

EL_GETPW_R_POSIX
EL_GETPW_R_DRAFT

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

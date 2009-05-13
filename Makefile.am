# pam_externalpass/Makefile.am

# Don't complain about "missing" standard GNU files
AUTOMAKE_OPTIONS = foreign

LIBTOOL=libtool
lib_LTLIBRARIES = libpam_externalpass.la
libpam_externalpass_la_SOURCES = pam_externalpass.c

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log config.guess config.sub
#	rm -f ltmain.sh

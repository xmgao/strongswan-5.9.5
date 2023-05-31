AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-otpalg.la
else
plugin_LTLIBRARIES = libstrongswan-otpalg.la
endif

libstrongswan_otpalg_la_SOURCES = \
	otpalg_plugin.h otpalg_plugin.c otpalg_crypter.c otpalg_crypter.h 

libstrongswan_otpalg_la_LDFLAGS = -module -avoid-version
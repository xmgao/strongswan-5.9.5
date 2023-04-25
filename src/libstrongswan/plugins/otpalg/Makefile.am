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
	otp_plugin.h otp_plugin.c otp_crypter.c otp_crypter.h 

libstrongswan_otpalg_la_LDFLAGS = -module -avoid-version
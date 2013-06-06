# Makefile.am
# Automake file for Pyreshark plugin (http://code.google.com/p/pyreshark)
#
# Copyright (c) 2013 by Eshed Shaham
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

INCLUDES = -I$(top_srcdir) -I$(includedir) `python-config --includes`

include Makefile.common

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

plugindir = @plugindir@
pythondir = $(datadir)/wireshark/python
pythonsubdirs = $(pythondir)/cal $(pythondir)/protocols

plugin_LTLIBRARIES = pyreshark.la
pyreshark_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(DISSECTOR_SRC) \
	$(DISSECTOR_SUPPORT_SRC) \
	$(DISSECTOR_INCLUDES)
pyreshark_la_LDFLAGS = -module -avoid-version
pyreshark_la_LIBADD = @PY_LIBS@ @PLUGIN_LIBS@
pyreshark_la_CFLAGS = @PY_CFLAGS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS = `python-config --ldflags`

CLEANFILES = \
	pyreshark \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	moduleinfo.nmake	\
	plugin.rc.in		\
	CMakeLists.txt

all: all-am ws_consts ws_types
	
ws_consts:	
	$(PYTHON) generate_ws_consts.py python/cal/ws_consts.py

ws_types:	
	cp templates/ws_types.py.$(VERSION_MAJOR)_$(VERSION_MINOR) python/cal/ws_types.py
    
install-data-am: install-pluginLTLIBRARIES install-python

install-python:
	$(MKDIR_P) $(datadir)/wireshark
	cp -fR python $(datadir)/wireshark/
	chmod -R a+r $(pythondir)
	

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build $(DISSECTOR_SRC) $(DISSECTOR_INCLUDES)

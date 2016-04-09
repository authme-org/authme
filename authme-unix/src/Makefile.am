#
#  Copyright 2005 Berin Lautenbach
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

## Source directory

h_sources = pauthme.h
c_sources = pauthme.c config.c 

library_h_sources = utils.h service.h json.h mpass.h mpass_openssl.h httpc.h httpc_curl.h
library_c_sources = utils.c service.c json.c mpass.c mpass_openssl.c httpc.c httpc_curl.c cnffile.c

authme_c_sources = authme.c

# First the convenience library for everything used by PAM module
# and the tool

noinst_LTLIBRARIES = libauthme.la
libauthme_la_SOURCES = $(library_c_sources) $(library_h_sources)

# Now the PAM module

library_includedir=$(includedir)/$(LIBRARY_NAME)-$(API_VERSION)/$(LIBRARY_NAME)#library_include_HEADERS = $(h_sources)

AM_CPPFLAGS = -I$(top_srcdir)

# securityexecdir = $(DESTDIR)$(libdir)/security

libsecurity_LTLIBRARIES= pam_authme.la
pam_authme_la_LIBADD= libauthme.la
pam_authme_la_SOURCES= $(h_sources) $(c_sources)
pam_authme_la_LDFLAGS= -avoid-version -module -lcrypt -lcurl

# Finally the tool.  NOTE: This is not installed at this time as it is
# primarily for testing

bin_PROGRAMS = authme
authme_SOURCES = $(authme_c_sources)
authme_LDADD = libauthme.la -lcurl
authme_LDFLAGS= -lcrypt -lcurl

install-exec-hook:
	rm -f $(libsecuritydir)/$(LIBRARY_NAME).la
	rm -f $(libsecuritydir)/$(LIBRARY_NAME).a

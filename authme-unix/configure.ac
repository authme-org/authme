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

dnl -----------------------------------------------
dnl Package name and version number (user defined)
dnl -----------------------------------------------

LIBRARY_NAME=pam_authme

#release versioning
MAJOR_VERSION=0
MINOR_VERSION=1
MICRO_VERSION=0

#API version 
API_VERSION=$MAJOR_VERSION.$MINOR_VERSION
AC_SUBST(API_VERSION)

#shared library versioning
LIBRARY_VERSION=0:1:0
#                       | | |
#                +------+ | +---+
#                |        |     |
#             current:revision:age
#                |        |     |
#                |        |     +- increment if interfaces have been added
#                |        |        set to zero if interfaces have been removed
#                                  or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed


dnl --------------------------------
dnl Package name and version number
dnl --------------------------------

AC_SUBST(LIBRARY_VERSION)

PACKAGE=$LIBRARY_NAME
AC_SUBST(LIBRARY_NAME)

VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION
RELEASE=$MAJOR_VERSION.$MINOR_VERSION
AC_SUBST(RELEASE)
AC_SUBST(VERSION)

dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT(authme, 0.1.0)
AC_CONFIG_SRCDIR([src/pauthme.h])
AM_CONFIG_HEADER(src/config.h)

AM_INIT_AUTOMAKE

dnl -----------------------------------------------
dnl Arguments
dnl -----------------------------------------------

# Left purely as a pointer to help down the track

AC_ARG_WITH(openldap,
        AC_HELP_STRING(--with-openldap,
                [Define OpenLDAP installation directory]),
LDFLAGS="${LDFLAGS} -L${withval}/lib"
CPPFLAGS="${CPPFLAGS} -I${withval}/include")

AC_ARG_WITH(service,
    [AC_HELP_STRING([--with-service],
        [Define the service URL @<:@default=https://www.authme.org/AuthMeWS/Svc@:>@])],
    [],
    [with_service=https://www.authme.org/AuthMeWS/Svc])

AC_ARG_WITH([libsecuritydir],
    [AC_HELP_STRING(--with-libsecuritydir,
        [Define directory in which to install the PAM module])],
    [], [with_libsecuritydir='$(libdir)/security'])

dnl -----------------------------------------------
dnl Checks for programs.
dnl -----------------------------------------------

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AM_SANITY_CHECK

AC_LANG_C

dnl -----------------------------------------------
dnl Required include files and libraries
dnl -----------------------------------------------

AC_MSG_CHECKING([for PAM headers])
AC_TRY_COMPILE([#include <security/pam_appl.h>
#include <security/pam_modules.h>],
[
int test = 1;
],
AC_MSG_RESULT([yes]),
AC_MSG_RESULT([no])
AC_ERROR(["Cannot find PAM header files"]))

dnl -----------------------------------------------
dnl Check for libcurl
dnl -----------------------------------------------

AC_MSG_CHECKING([for curl headers])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <curl/curl.h>]])],
   [AC_DEFINE(HAVE_CURL, [], [Curl found on system])
    AC_MSG_RESULT([yes])],
   [AC_MSG_RESULT([no])
    AC_ERROR(["Cannot find curl header files"])])
    
dnl -----------------------------------------------
dnl Check for LDAP functions that we require
dnl -----------------------------------------------

# AC_CHECK_LIB([ldap],
#  ldap_start_tls_s,
#  AC_DEFINE(AUTHME_HAVE_LDAP_START_TLS, [],
#    [Do we have ldap_start_tls_s on this platform?]),
#  AC_WARN([No TLS available on this platform]))

dnl -----------------------------------------------
dnl Check for required PAM flags
dnl -----------------------------------------------

AC_MSG_CHECKING([for PAM_AUTHTOK_RECOVER_ERR])
AC_TRY_COMPILE([#include <security/pam_appl.h>
#include <security/pam_modules.h>],
[
int test = PAM_AUTHTOK_RECOVER_ERR;
],
AC_MSG_RESULT([yes]),
AC_MSG_RESULT([no])
  AC_MSG_CHECKING([for PAM_AUTHTOK_RECOVERY_ERR])
  AC_TRY_COMPILE([#include <security/pam_appl.h>
  #include <security/pam_modules.h>],
  [
  int test = PAM_AUTHTOK_RECOVERY_ERR;
  ],
  AC_MSG_RESULT([yes])
  AC_DEFINE(PLDAP_AUTHTOK_RECOVER_IS_RECOVERY, [],
    [PAM_AUTHTOK_RECOVER_ERR is PAM_AUTHTOK_RECOVERY_ERR on this platform]),
  AC_MSG_RESULT([no])
  AC_MSG_ERROR(["Cannot find token for PAM_AUTHTOK_RECOVERY_ERR"])))

dnl -----------------------------------------------
dnl Check for OpenSSL
dnl -----------------------------------------------

# First check includes

AC_MSG_CHECKING([for OpenSSL headers])

AC_TRY_CPP([#include <openssl/opensslv.h>], 
   openssl_found=yes 
   AC_DEFINE(HAVE_OPENSSL, [], [OpenSSL found on system])
   [AC_MSG_RESULT([found])], 
   [AC_MSG_ERROR(["Unable to find OpenSSL headers"])]);

# Now check libs
# Note we keep both the base OPENSSL dir and /lib to handle
# both an installed version or a source dir

# As of 1.3 - use AC_TRY_LINK to check as AC_CHECK_LIB does
# the wrong thing

AC_MSG_CHECKING([for libcrypto])
AC_TRY_LINK([#include <openssl/evp.h>],
   [EVP_EncryptInit(NULL, NULL, NULL, NULL) ; return 0; ],
   [AC_MSG_RESULT([found])]
   openssllib_found=yes,
   [LIBS=$OLD_LIBS])

   if test -z "$openssllib_found" ; then

   LIBS=["${LIBS} -L${OPENSSL}/lib -lcrypto"]
   AC_TRY_LINK([#include <openssl/evp.h>],
     [EVP_EncryptInit(NULL, NULL, NULL, NULL) ; return 0; ],
      [AC_MSG_RESULT([found])]
      openssllib_found=yes,
      [LIBS=$OLD_LIBS]
          [AC_MSG_RESULT([no])]
          [AC_MSG_ERROR(["Unable to find libcrypto"])])

  fi

dnl -----------------------------------------------
dnl Configure final variable outputs
dnl -----------------------------------------------

AS_IF([test "x$with_service" != xno],
    [AC_DEFINE_UNQUOTED([AUTHME_SERVICE_URL], ["$with_service"],
               [Define default service URL (if any)])],
    [])

AC_SUBST([libsecuritydir], [$with_libsecuritydir])

dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_OUTPUT(Makefile \
          pauthme-0.1.pc \
          src/Makefile
)


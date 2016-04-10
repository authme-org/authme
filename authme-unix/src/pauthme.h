/*
*
* Copyright 2015 Berin Lautenbach
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#ifndef AUTHME_H
#define AUTHME_H

/* Autoconf configuration */
#include "config.h"

/* For the service component of the configuration */
#include "service.h"

/* Include module definitions for PAM */

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* Other useful includes */
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

/* For logging and other reasons */
#define AUTHME_MODULE_NAME "pam_authme v0.1.0"
/* For storing data in the pam subsystem */
#define AUTHME_CONFIG_DATA "pam_authme_config"

/* ---------------------------------------------------------------- *
 * PAM Defines that change from system to system
 * ---------------------------------------------------------------- */

#if defined (AUTHME_AUTHTOK_RECOVER_IS_RECOVERY)
// FreeBSD?
#  define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif

#ifndef PAM_EXTERN
#  define PAM_EXTERN extern
#endif

/* ---------------------------------------------------------------- *
 * authme_config
 * ---------------------------------------------------------------- */

/* This is the configuration for a particular PAM session */

typedef struct authme_config_s {

#define AUTHME_PC_ID   0xF6786

    int        pc_id;               /* An identifier to try to ensure
                                       the structure is valid */
    char       pc_do_debug;         /* Was "debug" set in pam.conf? */
    char       pc_silent;           /* Suppress messages */

    /* These are filled out if the user is authenticated */
    char     * pc_userid;           /* What was the userid we used? */

    /* Configuration for the service */
    authme_service_config_t * pc_psc;
    
} authme_config_t;

/* Configuration functions */

/* Clean up the configuration */
void authme_pam_cleanup(pam_handle_t *pamh, void *data, int error_status);

/* Create a new configuration */
authme_config_t * authme_config_create(void);

/* ---------------------------------------------------------------- *
 * Utility functions (utils.c)
 * ---------------------------------------------------------------- */

/* Log to syslog in the required fashion */
void authme_do_log(char do_debug, 
                  int priority, 
                  const char * format, ...);

/* Split input arguments from pam.conf */
int authme_arg_split (char * arg, char **cmd, char ** var);

/* Days since 1970 - for shadow password entries */

int
authme_days_since_1970(void);

/* ---------------------------------------------------------------- *
 * PAM functions (authme.c)
 * ---------------------------------------------------------------- */

int
authme_send_pam_msg(pam_handle_t *pamh, 
                   authme_config_t * pc, const char * msg);


#endif // AUTHME_H


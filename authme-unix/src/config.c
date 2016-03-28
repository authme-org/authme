
/* config.c
 *
 * Copyright 2005 Berin Lautenbach
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

#include "pauthme.h"
#include "utils.h"

#include <strings.h>
#include <syslog.h>

/* ---------------------------------------------------------------- *
 * authme_pam_cleanup - Destroy a configuration
 * ---------------------------------------------------------------- */
 
void authme_pam_cleanup(pam_handle_t *pamh, void *data, int error_status)
{

    authme_config_t * pc;
    int err;

    if (data == NULL)
        /* Nothing to do - probably an error! */
        return;

    pc = (authme_config_t *) data;

    if (pc->pc_id != AUTHME_PC_ID) 
        {
            authme_do_log(FALSE,
                         LOG_ERR, 
                         "(%s) Asked to destroy non authme structure",
                         AUTHME_MODULE_NAME);
            return;
    }

    authme_do_log(TRUE, 
                 LOG_DEBUG, 
                 "(%s) cleaning up config",
                 AUTHME_MODULE_NAME);

    if (pc->pc_userid != NULL)
        free (pc->pc_userid);
    if (pc->pc_psc != NULL)
        /* Delete the service configuration */
        authme_service_config_free(pc->pc_psc);

    /* Now delete the actual config */
    free (pc);

}

/* ---------------------------------------------------------------- *
 * authme_config_create - create a new config structure
 * ---------------------------------------------------------------- */

authme_config_t * authme_config_create(void)
{

    authme_config_t * pc;

    pc = (authme_config_t *) malloc(sizeof(*pc));

    if (pc == NULL)
    {
        authme_do_log(FALSE, 
                     LOG_CRIT, 
                     "(%s) Bailing due to memory allocation problem"
                     AUTHME_MODULE_NAME);
        return NULL;
    }

    /* Set the identifier - probably a waste of time, but paranoia
       sometimes pays off. */

    pc->pc_id = AUTHME_PC_ID;

    /* Default values for config */
    pc->pc_do_debug = FALSE;
    pc->pc_silent = FALSE;
    pc->pc_userid = NULL;

    /* Service configuration */
    pc->pc_psc = authme_service_config_create();

    /* Sanity check */
    if (pc->pc_psc == NULL)
    {
        authme_do_log(FALSE, 
                     LOG_CRIT, 
                     "(%s) Error creating service configuration",
                     AUTHME_MODULE_NAME);
        return NULL;
    }

    return pc;
        
}


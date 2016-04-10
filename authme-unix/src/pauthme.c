/* pauthme.c
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
#include "config.h"
#include "utils.h"

#include <strings.h>
#include <syslog.h>
#include <stdio.h>


/* ---------------------------------------------------------------- *
 * pldap_send_pam_msg
 * ---------------------------------------------------------------- */

int
authme_send_pam_msg(pam_handle_t *pamh, authme_config_t * pc, const char * msg)
{

    int err;

    /* Send a message to the user */
    struct pam_conv *pcnv;
    struct pam_message *pmsg;
    struct pam_response *prsp;

    if (pc->pc_silent)
    {
        authme_do_log(pc->pc_do_debug, LOG_DEBUG,
                     "(%s) Suppressing message to PAM",
                     AUTHME_MODULE_NAME);
        return PAM_SUCCESS;
    }

    if ((err = pam_get_item(pamh, 
                            PAM_CONV, 
                            (const void **) &pcnv)) != PAM_SUCCESS)
    {

        authme_do_log(FALSE, LOG_ERR,
                     "(%s) Error retrieving PAM_CONV - %s",
                     AUTHME_MODULE_NAME,
                     pam_strerror(pamh, err));
        return PAM_CONV_ERR;
    }

    if (pcnv == NULL)
    {
        authme_do_log(FALSE, LOG_ERR, "(%s) Error retrieving PAM_CONV",
                     AUTHME_MODULE_NAME);
        return PAM_CONV_ERR;
    }

    /* Have the conversation function! */
    pmsg = (struct pam_message *) calloc(1, sizeof(*pmsg));
    if (pmsg == NULL)
    {
        authme_do_log(FALSE, LOG_CRIT, "(%s) Unable to obtain memory",
                     AUTHME_MODULE_NAME);
        return PAM_SYSTEM_ERR;
    }

    pmsg->msg_style = PAM_TEXT_INFO;
    pmsg->msg = msg;
    prsp = NULL;
    
    (pcnv->conv)(1, (const struct pam_message **) &pmsg, &prsp, 
                 pcnv->appdata_ptr);

    /* Clean up */
    free (prsp);
    free (pmsg);

    return PAM_SUCCESS;
}

/* ---------------------------------------------------------------- *
 * authme_get_pam_config
 * ---------------------------------------------------------------- */

int
authme_get_config_from_pam(pam_handle_t * pamh, authme_config_t **pc)
{
    int err, i;

    /* Check for a pre-existing config */
    if ((err = pam_get_data(pamh, AUTHME_CONFIG_DATA, 
                            (const void **) (pc))) != PAM_SUCCESS)
    {
        /* Check to see why */
        if (err == PAM_NO_MODULE_DATA)
        {
            /* Needs to be created */
            if ((*pc = authme_config_create()) == NULL)
            {
                authme_do_log(FALSE, LOG_CRIT, 
                             "(%s) Cannot create config structure",
                             AUTHME_MODULE_NAME);
                return PAM_SYSTEM_ERR;
            }

            /* Have the config - save */
            if (pam_set_data(pamh, AUTHME_CONFIG_DATA, *pc, 
                             authme_pam_cleanup) !=
                PAM_SUCCESS) 
            {
                authme_do_log(FALSE, LOG_CRIT, 
                             "(%s) Cannot store config structure",
                             AUTHME_MODULE_NAME);
                return PAM_SYSTEM_ERR;
            }
        }
        else
        {

            /* Unknown retrieval error */
            authme_do_log(FALSE, LOG_CRIT,
                         "(%s) Unknown error retrieving config - %s",
                         AUTHME_MODULE_NAME, pam_strerror(pamh, err));
            return PAM_SYSTEM_ERR;
        }
    }
            
    return PAM_SUCCESS;
}

/* ---------------------------------------------------------------- *
 * authme_read_args
 * ---------------------------------------------------------------- */

int
authme_read_args(authme_config_t * pc, int flags, int argc, 
                const char ** argv)
{
    int i, err;
    char * arg, * cmd, * var;

    for (i = 0; i < argc; ++i)
    {
        arg = strdup(argv[i]);
        err = authme_arg_split(arg, &cmd, &var);
        if (err == 0)
        {
            authme_do_log(FALSE, LOG_ERR, "(%s) Unknown error processing args",
                         AUTHME_MODULE_NAME);
        }
        
        else if (strcasecmp(cmd, "url") == 0)
        {
            if (err != 2) 
                authme_do_log(FALSE, LOG_ERR, "(%s) URL requires argument",
                             AUTHME_MODULE_NAME);
            else
            {
                /* AUTHME server to connect to */
                if (pc->pc_psc->psc_url != NULL) {
                    free(pc->pc_psc->psc_url);
                }
                pc->pc_psc->psc_url = strdup(var);
            }
        }
        else if (strcasecmp(cmd, "serverid") == 0)
        {
            if (err != 2) 
                authme_do_log(FALSE, LOG_ERR, "(%s) serverid requires argument",
                             AUTHME_MODULE_NAME);
            else
            {
                /* Server ID to pass to the service */
                if (pc->pc_psc->psc_server_id != NULL) {
                    free(pc->pc_psc->psc_server_id);
                }
                pc->pc_psc->psc_server_id = strdup(var);
            }
        }
        else if (strcasecmp(cmd, "debug") == 0)
        {    

            authme_do_log(TRUE, LOG_DEBUG,
                         "(%s) Enabling debug",
                         AUTHME_MODULE_NAME);
            pc->pc_do_debug = TRUE;
        }
        else
        {
            authme_do_log(FALSE, LOG_ERR,
                         "(%s) Unknown option - %s",
                         AUTHME_MODULE_NAME,
                         argv[i]);
        }
        free (arg);
    }
    return PAM_SUCCESS;

}

/* ---------------------------------------------------------------- *
 * authme_request_password
 * ---------------------------------------------------------------- */

/* Single function to ask for a password */
int
authme_request_password(pam_handle_t * pamh, const char * prompt,
                       const char **password)
{
    int err;
    struct pam_conv *pcnv;
    struct pam_message *pmsg;
    struct pam_response *prsp;


    authme_do_log(TRUE, LOG_DEBUG,
                 "(%s) Asking for password",
                 AUTHME_MODULE_NAME);
    return PAM_SUCCESS;

    /* Old stuff under here */

    if ((err = pam_get_item(pamh, 
                            PAM_CONV, 
                            (const void **) &pcnv)) != PAM_SUCCESS)
    {

        authme_do_log(FALSE, LOG_ERR,
                     "(%s) Error retrieving PAM_CONV - %s",
                     AUTHME_MODULE_NAME,
                     pam_strerror(pamh, err));
        return err;
    }

    if (pcnv == NULL)
    {
        authme_do_log(FALSE, LOG_ERR, "(%s) Error retrieving PAM_CONV",
                     AUTHME_MODULE_NAME);
        return PAM_CONV_ERR;
    }

    /* Have the conversation function! */
    pmsg = (struct pam_message *) calloc(1, sizeof(*pmsg));
    if (pmsg == NULL)
    {
        authme_do_log(FALSE, LOG_CRIT, "(%s) Unable to obtain memory",
                     AUTHME_MODULE_NAME);
        return PAM_SYSTEM_ERR;
    }

    pmsg->msg_style = PAM_PROMPT_ECHO_OFF;
    pmsg->msg = prompt;
    prsp = NULL;

    (pcnv->conv)(1, (const struct pam_message **) &pmsg, &prsp, 
                 pcnv->appdata_ptr);

    /* Retrieve the password ! */
    *password = strdup(prsp[0].resp);
                
    /* Clean up */
    free (prsp);
    free (pmsg);

    return PAM_SUCCESS;

}

/* ---------------------------------------------------------------- *
 * authme_send_user_msg
 * ---------------------------------------------------------------- */

int
authme_send_user_msg(pam_handle_t * pamh, const char * msg)

{
    int err;
    struct pam_conv *pcnv;
    struct pam_message *pmsg;
    struct pam_response *prsp;


    if ((err = pam_get_item(pamh, 
                            PAM_CONV, 
                            (const void **) &pcnv)) != PAM_SUCCESS)
    {

        authme_do_log(FALSE, LOG_ERR,
                     "(%s) Error retrieving PAM_CONV - %s",
                     AUTHME_MODULE_NAME,
                     pam_strerror(pamh, err));
        return err;
    }

    if (pcnv == NULL)
    {
        authme_do_log(FALSE, LOG_ERR, "(%s) Error retrieving PAM_CONV",
                     AUTHME_MODULE_NAME);
        return PAM_CONV_ERR;
    }

    /* Have the conversation function! */
    pmsg = (struct pam_message *) calloc (1, sizeof(*pmsg));
    if (pmsg == NULL)
    {
        authme_do_log(FALSE, LOG_CRIT, "(%s) Unable to obtain memory",
                     AUTHME_MODULE_NAME);
        return PAM_SYSTEM_ERR;
    }

    pmsg->msg_style = PAM_TEXT_INFO;
    pmsg->msg = msg;
    prsp = NULL;

    (pcnv->conv)(1, (const struct pam_message **) &pmsg, &prsp, 
                 pcnv->appdata_ptr);

    /* Clean up */
    free (prsp);
    free (pmsg);

    return PAM_SUCCESS;

}

/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_chauthtok
 * ---------------------------------------------------------------- */

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, 
                                int argc, const char **argv) 

{

    /* This doesn't make sense for this module - return an error
     * rather than pretend everything is OK */

    return PAM_AUTH_ERR;

}


/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_acct_mgmt
 * ---------------------------------------------------------------- */

/*
 * Authenticated user - is everything OK for them to login?
 */

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, 
                                int argc, const char **argv) 

{

    /* By default OK - this is a pure authentication module for now */

    return PAM_SUCCESS;

}


/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_authenticate
 * ---------------------------------------------------------------- */
                 

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
                    const char **argv)
{

    int err;
    authme_config_t * pc;
    char * username;           /* Returned by the PAM library */

    /* This is the main function called by the library for a user
     * logging in.
     */

    /* Check for a pre-existing config */
    if ((err = authme_get_config_from_pam(pamh, &pc)) != PAM_SUCCESS)
        return err;

    /* At this point we have a configuration structure - 
     * read the arguments */

    if ((err = authme_read_args(pc, flags, argc, argv)) != PAM_SUCCESS)
        return err;

    /* Sanity Check */
    if (pc == NULL || pc->pc_psc == NULL)
        return PAM_SYSTEM_ERR;

    /* Find the user id we are working with */
    if ((err = pam_get_user(pamh, (const char **) &username, 
                            "Username")) != PAM_SUCCESS)
        return err;

    pc->pc_userid = strdup(username);

    /* Now we read the user's configuration file */
    if ((err = authme_load_user_cnf(pc->pc_psc, pc->pc_userid)) != AUTHME_ERR_OK)
        return PAM_USER_UNKNOWN;

    /* Did we get a service user ID? */
    if (pc->pc_psc->psc_user_id != NULL)
    {
        authme_do_log(pc->pc_do_debug, LOG_DEBUG,
                      "(%s) pam_sm_authenticate mapped to service id: %s",
                      AUTHME_MODULE_NAME, pc->pc_psc->psc_user_id);
    }
    
    authme_do_log(pc->pc_do_debug, LOG_DEBUG,
                 "(%s) pam_sm_authenticate called",
                 AUTHME_MODULE_NAME);

    /* OK - Loaded everything we can.  Do we have enough? */
    if (pc->pc_psc->psc_url == NULL)
    {
        authme_do_log(pc->pc_do_debug, LOG_ERR,
                     "(%s) pam_sm_authenticate called without URL defined",
                     AUTHME_MODULE_NAME);
        return PAM_SERVICE_ERR;
    }

    if (pc->pc_psc->psc_user_id == NULL)
    {
        authme_do_log(pc->pc_do_debug, LOG_ERR,
                     "(%s) pam_sm_authenticate called without userid defined",
                     AUTHME_MODULE_NAME);
        return PAM_SERVICE_ERR;
    }

    if (pc->pc_psc->psc_server_id == NULL)
    {
        authme_do_log(pc->pc_do_debug, LOG_ERR,
                     "(%s) pam_sm_authenticate called without Server ID defined",
                     AUTHME_MODULE_NAME);
        return PAM_SERVICE_ERR;
    }

    /* Execute */
    authme_service_init();
    authme_err_t perr = authme_start_svc_check(pc->pc_psc);
    if (perr == AUTHME_ERR_USER_UNKNOWN) 
    {
        authme_do_log(pc->pc_do_debug, LOG_WARNING,
                      "(%s) service did not recognise user ID %s",
                     AUTHME_MODULE_NAME, pc->pc_psc->psc_user_id);
        authme_service_shutdown();
        return PAM_USER_UNKNOWN;
    }
    if (perr != AUTHME_ERR_OK)
    {
        authme_do_log(pc->pc_do_debug, LOG_WARNING,
                     "(%s) service returned error: %s"
                     AUTHME_MODULE_NAME, pc->pc_psc->psc_last_error);
        authme_service_shutdown();
        return PAM_SERVICE_ERR;
    }

    /* Tell the user all good */
    authme_send_user_msg(pamh, "Waiting on Authme service response....");

    /* OK - We did a good initial request, now we loop until we get
     * a service response or we time out
     */

    int i = 0;
    for (i = 0; i < 60; ++i)
    {
        /* First sleep to let the user do something */
        sleep(1);

        /* Check the current status on the service */
        perr = authme_get_svc_check_status(pc->pc_psc);
        if (perr == AUTHME_ERR_OK)
        {
            if (pc->pc_psc->psc_check_status == AUTHME_STATUS_APPROVED)
            {
                authme_do_log(pc->pc_do_debug, LOG_INFO,
                             "(%s) user %s approved by service",
                             AUTHME_MODULE_NAME, pc->pc_psc->psc_user_id);
                authme_service_shutdown();
                return PAM_SUCCESS;
            }
            if (pc->pc_psc->psc_check_status == AUTHME_STATUS_DECLINED) {
                authme_do_log(pc->pc_do_debug, LOG_WARNING,
                             "(%s) user %s (%s) denied by service",
                             AUTHME_MODULE_NAME, pc->pc_userid,
                             pc->pc_psc->psc_user_id);
                authme_service_shutdown();
                return PAM_AUTH_ERR;
            }
        }
        else {
            authme_do_log(pc->pc_do_debug, LOG_WARNING,
                         "(%s) service error: %s",
                         AUTHME_MODULE_NAME, pc->pc_psc->psc_last_error);
            authme_service_shutdown();
            return PAM_SERVICE_ERR;
        }
    }

    
    authme_do_log(pc->pc_do_debug, LOG_WARNING,
                 "(%s) service timed out for user %s (%s)",
                 AUTHME_MODULE_NAME, pc->pc_userid, pc->pc_psc->psc_user_id);

    authme_service_shutdown();
    return PAM_AUTH_ERR;
    
}


/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_setcred
 * ---------------------------------------------------------------- */

/* This function is fairly irrelevant for AUTHME at the moment - once
 * you are authenticated - that's it! */

PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
               const char **argv)
{

    return PAM_SUCCESS;

}

/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_open_session
 * ---------------------------------------------------------------- */

PAM_EXTERN int
pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
                    const char **argv)
{

    int err;
    const char * username;

    /* Get the username */
    if ((err = pam_get_user(pamh, &username, "Username")) != PAM_SUCCESS)
        return err;


    /* Do a log and not much else! */
    
    authme_do_log(FALSE, LOG_NOTICE,
                 "(%s) Session opened for user %s",
                 AUTHME_MODULE_NAME,
                 username);
    
    return PAM_SUCCESS;

}

/* ---------------------------------------------------------------- *
 * PAM Function - pam_sm_close_session
 * ---------------------------------------------------------------- */

PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
                    const char **argv)
{

    int err;
    const char * username;
    authme_config_t * pc;

    /* Check for a pre-existing config */
    if ((err = authme_get_config_from_pam(pamh, &pc)) != PAM_SUCCESS)
        return err;

    /* Get the username */
    if ((err = pam_get_user(pamh, &username, "Username")) != PAM_SUCCESS)
        return err;
    
    /* Do a log */
    
    authme_do_log(FALSE, LOG_NOTICE,
                 "(%s) Session closed for user %s",
                 AUTHME_MODULE_NAME,
                 username);
    
    return PAM_SUCCESS;

}

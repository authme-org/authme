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

#include "utils.h"
#include "service.h"
#include "json.h"

#if defined WIN32
#include "stdafx.h"
#include <ShlObj.h>
#include "helpers.h"
#define strcasecmp _stricmp
#else
#include <pwd.h>
#include <errno.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>

#include "service.h"

/*
 * Load the various configuration file items
 */

#if defined WIN32
#define DIR_SEPARATOR "\\"
#else
#define DIR_SEPARATOR "/"
#endif

 /* ---------------------------------------------------------------- *
 * Some Utilities
 * ---------------------------------------------------------------- */
#if defined WIN32
char *
get_user_dir()
{
	PWSTR wdir;
	char * ret;

	if (!SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &wdir)))
	{
		return NULL;
	}

	ret = wStrToStrDupN(wdir, wcslen(wdir));
	CoTaskMemFree(wdir);

	return ret;
}

#else

char *
get_user_dir()
{

    /* A bit complicated but thread safe */
    struct passwd pw, *pw_res;
    char * bfr, *ret;
    int res;
    long bfr_len = sysconf(_SC_GETPW_R_SIZE_MAX);

    ret = NULL;
    
    if (bfr_len == -1)
        // Give up now
        return NULL;

    if ((bfr = (char *) malloc (bfr_len)) == NULL)
        return NULL;

    /* Find out current user details */
    res = getpwuid_r(getuid(), &pw, bfr, bfr_len, &pw_res);
    while (res == ERANGE)
    {
        free(bfr);
        bfr_len *= 2;
        if ((bfr = (char *) malloc (bfr_len)) == NULL)
            return NULL;

        res = getpwuid_r(getuid(), &pw, bfr, bfr_len, &pw_res);
    }

    if (res == 0 && pw_res != NULL)
    {
        ret = strdup(pw.pw_dir);
    }

    free(bfr);
	return ret;
}


#endif

char * get_default_key_file_name()
{
	char * ret = NULL;
	char * base = get_user_dir();

	bfr_t * b = new_bfr();

	append_bfr(b, base);
    append_bfr(b, DIR_SEPARATOR);
	append_bfr(b, "authme.key");

	ret = strdup(b->b);
	free_bfr(b);
	free(base);

	return ret;
}

/* ---------------------------------------------------------------- *
 * Line Parsing
 * ---------------------------------------------------------------- */

int
authme_cnf_parse_line(FILE * in, char ** command, char ** arg, 
                     char * buf, size_t buf_len)
{
    int done = 0;
    unsigned int i = 0;
    unsigned int max = 0;

    while (!done)
    {

        i = 0;
        
        /* Parse a single line of the input file */
        if (fgets(buf, (int) buf_len, in) == NULL)
            return -1;

        /* Find first non white space character */
        max = (unsigned int) strlen(buf);
        i = (unsigned int) json_skip_white_space(buf, i, max);

        if (i < max && buf[i] != '#') 
        {
            /* Non comment line! */
            *command = &buf[i];
            while (buf[i] != '\0' &&
                   buf[i] != ' ' &&
                   buf[i] != '\t' &&
                   buf[i] != '\r' &&
                   buf[i] != '\n' &&
                   i < max)
                ++i;

            if (buf[i] == '\0')
            {
                /* Command without an argument */
                *arg = NULL;
                return 0;
            }

            if (i >= max)
                /* Badness */
                return -1;

            buf[i] = '\0';
            i++;

            i = (unsigned int) json_skip_white_space(buf, i, max);
            *arg = &buf[i];

            /* Now find end of argument */
            while (buf[i] != '\0' &&
                   buf[i] != ' ' &&
                   buf[i] != '\t' &&
                   buf[i] != '\r' &&
                   buf[i] != '\n' &&
                   buf[i] != '#' &&
                   i < max)
                ++i;

            if (i > max)
                return -1;

            buf[i] = '\0';

            return 0;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------- *
 * authme_load_user_cnf
 * ---------------------------------------------------------------- */

authme_err_t
authme_load_user_cnf(authme_service_config_t *psc, char * username)
{

	char * n = username;
	bfr_t * b;

	char * base_dir;

	base_dir = get_user_dir();
	if (base_dir == NULL)
		return AUTHME_ERR_USER_UNKNOWN;

	b = new_bfr();
	append_bfr(b, base_dir);
#if defined WIN32
	append_bfr(b, "\\.authme");
#else
    append_bfr(b, "/.authme");
#endif

    FILE *in = fopen(b->b, "rt");
    free_bfr(b);
    
    if (in == NULL)
        return AUTHME_ERR_FILE_OPEN;    /* This is not really an error */

	authme_err_t ret = authme_load_cnf(psc, in, 0);

	fclose(in);

	return ret;
}


/* ---------------------------------------------------------------- *
 * authme_load_cnf
 * ---------------------------------------------------------------- */

/* Given a configuration file - load data into the provided service 
 * config. 
 *
 * The input_file is previously opened to allow the caller to pass
 * arbitrary config files
 *
 * the flags variable tells us what *not* to load from the file
*/

authme_err_t
authme_load_cnf(authme_service_config_t * psc, FILE * input_file, int flags)
{
    /* Line by line scan */
    
    char buf[1024];
    char * command, * arg;
    while (authme_cnf_parse_line(input_file, &command, &arg, buf, 1024) == 0)
    {
        if (strcasecmp(command, "ServiceUserId") == 0)
        {
			if (!(flags & AUTHME_CNF_IGNORE_USER_ID))
			{
				if (psc->psc_user_id != NULL)
					free(psc->psc_user_id);
				psc->psc_user_id = strdup(arg);
			}
        }
        else if (strcasecmp(command, "ServiceURL") == 0)
        {
			if (!(flags & AUTHME_CNF_IGNORE_SERVICE_URL))
			{
				if (psc->psc_url != NULL)
					free(psc->psc_url);
				psc->psc_url = strdup(arg);
			}
        }
		else if (strcasecmp(command, "KeyFileName") == 0)
		{
			if (!(flags & AUTHME_CNF_IGNORE_KEY_FILENAME))
			{
				if (psc->psc_key_file != NULL)
					free(psc->psc_key_file);
				psc->psc_key_file = strdup(arg);
			}
		}
		else if (strcasecmp(command, "KeyFilePass") == 0)
		{
			if (!(flags & AUTHME_CNF_IGNORE_KEY_FILENAME))
			{
				if (psc->psc_key_file_pass.password_data != NULL)
				{
					free(psc->psc_key_file_pass.password_data);
					psc->psc_key_file_pass.password_data = NULL;
				}

				/* Now have to split it apart */
				if (strlen(arg) < 3 || arg[1] != '!')
					return AUTHME_ERR_UNKNOWN_CNF_OPTION;

				psc->psc_key_file_pass.password_format = arg[0] - '0';
				psc->psc_key_file_pass.password_data = strdup(&arg[2]);
			}
		}
		else
        {
            bfr_t * e = new_bfr();
            append_bfr(e, "Unknown command option: ");
            append_bfr(e, command);
            psc->psc_last_error = strdup(e->b);
            free_bfr(e);
            return AUTHME_ERR_UNKNOWN_CNF_OPTION;
        }
    }
    
    return AUTHME_ERR_OK;
}

/* ---------------------------------------------------------------- *
 * authme_load_system_cnf
 * ---------------------------------------------------------------- */

/* Find the file for the system configuration */

authme_err_t
authme_load_system_cnf(authme_service_config_t * psc, int flags)
{
    authme_err_t ret;

    /* Naughty - but for now on *nix default to /etc/authme/authme.cnf */

#if !defined W32
    FILE *in = fopen("/etc/authme/authme.cnf", "rt");
#endif
    if (in == NULL)
        return AUTHME_ERR_FILE_OPEN;    /* This is not really an error */

    ret = authme_load_cnf(psc, in, flags);

    fclose(in);

    return ret;
}

/* ---------------------------------------------------------------- *
* authme_save_user_cnf
* ---------------------------------------------------------------- */

/* Save the file back to the user's directory - really for use by
 * GUI on Windows */

authme_err_t
authme_save_user_cnf(authme_service_config_t * psc, int flags, char * username)
{

	char * n = username;
	bfr_t * b;

	char * base_dir;

	base_dir = get_user_dir();
	if (base_dir == NULL)
		return AUTHME_ERR_FILE_OPEN;

	b = new_bfr();
	append_bfr(b, base_dir);
#if defined WIN32
	append_bfr(b, "\\.authme");
#else
	append_bfr(b, "/.authme");
#endif

	FILE *out = fopen(b->b, "wt");
	free_bfr(b);

	if (out == NULL)
		return AUTHME_ERR_FILE_OPEN;

	/* Default output */
	fprintf(out, "# Authme %s configuration file\n\n", AUTHME_LIBRARY_VERSION);
	if (psc->psc_url != NULL && !(flags & AUTHME_CNF_IGNORE_SERVICE_URL))
		fprintf(out, "ServiceURL %s\n", psc->psc_url);
	if (psc->psc_user_id != NULL && !(flags & AUTHME_CNF_IGNORE_USER_ID))
		fprintf(out, "ServiceUserId %s\n", psc->psc_user_id);
	if (psc->psc_key_file != NULL && !(flags & AUTHME_CNF_IGNORE_KEY_FILENAME))
		fprintf(out, "KeyFileName %s\n", psc->psc_key_file);

	/* The password for the key file if it exists */
	if (psc->psc_key_file_pass.password_data != NULL && !(flags & AUTHME_CNF_IGNORE_KEY_FILE_PASS))
	{
		fprintf(out, "KeyFilePass %c!%s", '0' + psc->psc_key_file_pass.password_format, psc->psc_key_file_pass.password_data);
	}

	fclose(out);

	return AUTHME_ERR_OK;

}


/* utils.c
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

#ifdef WIN32
#	include "stdafx.h"
#endif

#include "utils.h"

#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifndef WIN32
#	include <syslog.h>
#endif

#include <stdarg.h>

#ifndef WIN32

/* ---------------------------------------------------------------- *
 * authme_do_log - Log as appropriate to syslog
 * ---------------------------------------------------------------- */

void authme_do_log(char do_debug, int priority, const char * format, ...)
{

    va_list ap;

    /* Log to the syslog in the manner required by the pam programmers
     * notes.  I.e. set the facility to LOG_AUTHPRIV and only log
     * debug messages if debug argument was set
     */

    if (priority == LOG_DEBUG && do_debug == FALSE)
        return;

    va_start(ap, format);

    /* openlog(AUTHME_MODULE_NAME, 0, LOG_AUTHPRIV);*/
    vsyslog(priority, format, ap);

    /* We closelog for completeness - this is probably cool for now, but
     * might get a bit unwieldy if we start to write lots of messages */

    /* closelog(); */

    va_end(ap);
}

#endif

/* ---------------------------------------------------------------- *
 * authme_arg_split - split arguments into command/variable
 * ---------------------------------------------------------------- */

/* pam_authme arguments in pam.conf take the form
 * 
 * cmd=variable
 *
 * This functions splits a single input into its two parts */

int
authme_arg_split (char * arg, char **cmd, char ** var)
{

    char * p;

    p = arg;
    while (*p == '\t' || *p == ' ')
        p++;

    if (*p == '\0')
        /* Whoops!  Nothing found! */
        return 0;

    *cmd = p;

    p = strchr(arg, '=');
    if (p == NULL)
        {
            return 1;
        }

    *(p++) = '\0';
    while (*p == '\t' || *p == ' ')
        p++;

    *var = p;
    return 2;

}


/* ---------------------------------------------------------------- *
 * authme_days_since_1970 - Determine days since 1970
 * ---------------------------------------------------------------- */
    
long
authme_days_since_1970(void)
{

    time_t t;
    long int seconds_per_day;

    seconds_per_day = 60 * 60 * 24;

    /* Get current time in seconds */
    t = time(NULL);
    

    return (long) (t / seconds_per_day);

}

/* ---------------------------------------------------------------- *
 * Buffer Manipulation
 * ---------------------------------------------------------------- */

bfr_t * 
new_bfr(void)
{
    bfr_t * ret;

    ret = (bfr_t *) malloc (sizeof(bfr_t));
    ret->s = 1024;
    ret->b = (char *) malloc (ret->s);
    ret->b[0] = '\0';

    return ret;

}

    
void
free_bfr(bfr_t * bfr)
{

    if (bfr != NULL)
    {
        if (bfr->b != NULL)
            free (bfr->b);
        free (bfr);
    }
}

void 
check_bfr(bfr_t * bfr, size_t sz)
{

    if (bfr->s > sz)
        return;

    do
    {
        bfr->s = bfr->s * 2;
    } while (bfr->s < sz);

}

void append_bfr(bfr_t * bfr, const char * str)
{

	char * ret;
	size_t bs, as;

	bs = strlen(bfr->b);
	as = strlen(str);

	if (bs + as >= bfr->s) {
		do {
			bfr->s = bfr->s * 2;
		} while (bs + as > bfr->s);

		ret = (char *)malloc(bfr->s);
		strcpy(ret, bfr->b);
		free(bfr->b);
		bfr->b = ret;
	}

	strcat(bfr->b, str);

}




/* utils.h
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

#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>

/* ---------------------------------------------------------------- *
 * Useful defines
 * ---------------------------------------------------------------- */

#ifndef FALSE
#  define FALSE 0
#endif

#ifndef TRUE
#  define TRUE 1
#endif

#define AUTHME_LSA_NAME  "AUTHME_LSA_0_1"

/* ---------------------------------------------------------------- *
 * Buffer Manipulation
 * ---------------------------------------------------------------- */

typedef struct bfr_s {

    size_t     s;     /* Size of current buffer */
    char *     b;     /* Buffer */

    size_t     i;     /* An index pointer - be careful when threaded! */

} bfr_t;

bfr_t * new_bfr(void);
void free_bfr(bfr_t * bfr);
void check_bfr(bfr_t * bfr, size_t sz);
void append_bfr(bfr_t * brf, const char * str);

/* ---------------------------------------------------------------- *
* Log Handling
* ---------------------------------------------------------------- */

#ifndef WIN32
void authme_do_log(char do_debug, int priority, const char * format, ...);
#endif

#endif

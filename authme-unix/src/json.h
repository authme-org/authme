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

#ifndef AUTHME_JSON_H
#define AUTHME_JSON_H

#ifndef WIN32
#	include "config.h"
#endif

#include <stddef.h>

/*
 * JSON objects
 *
 */

typedef struct json_s {

    /* First the type of this element */

    enum json_types {
        OBJECT,
        OBJECTELEMENT,
        ARRAY,
        ARRAYELEMENT,
        JSTRING,
        NUMBER,
        JTRUE,
        JFALSE,
        JNULL
    } type;

    /* Now the actual values */
    char *   js_object_name;
    char *   js_str_value;
    long     js_number_value;
    char     js_bool_value;

    /* Child value for objects and arrays */
    struct json_s * js_next;
    struct json_s * js_child;


} json_t;


json_t *
json_parse(unsigned char * b);

char *
json_to_string(json_t * json);

json_t * 
json_new(void);

json_t *
json_new_string(char * val, char * key);

void
json_free(json_t * json);

json_t *
json_get_item_by_key(json_t * obj, char * key);

/* Used elsewhere in library */
size_t
json_skip_white_space(unsigned char * b, size_t i, size_t max);
#endif

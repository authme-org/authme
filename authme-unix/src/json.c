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

#ifdef WIN32
#include "stdafx.h"
#else
#	include "config.h"
#endif

#include "json.h"

#include <stdlib.h>

#ifdef HAVE_STRINGS_H
#   include <strings.h>
#endif

#include <string.h>

#include <stdio.h>

#ifndef WIN32
#	include <syslog.h>
#define strnicmp strncasecmp
#define _snprintf snprintf
#endif

#define _JSON_CHECK_INDEX(I,M,R) if (I>= M) return R

size_t
json_scan_for_char(unsigned char * b, size_t i,
					size_t max, unsigned char c) {
        
    while (i < max && b[i] != c)
        i++;
        
    return i;
}

size_t
json_parse_string(unsigned char * b, size_t i,
				size_t max, char ** ret);

size_t
json_parse_value(unsigned char * b, size_t i,
				size_t max, json_t * ret);

size_t
json_parse_object(unsigned char * b, size_t i,
				size_t max, json_t * ret);

size_t
json_parse_array(unsigned char * b, size_t i,
				size_t max, json_t * ret);

char *
json_to_string_object(json_t * json, char * str, size_t * sz);

char *
json_to_string_value(json_t * json, char * str, size_t *sz);

char *
json_to_string_array(json_t * json, char * str, size_t * sz);

char *
json_escape_string(char * str);


/* ---------------------------------------------------------------- *
 * Create a new json_t object
 * ---------------------------------------------------------------- */

json_t * 
json_new(void)
{

    json_t * ret;

    /* allocate memory */
    ret = (json_t *) malloc (sizeof(json_t));

    /* Set type */
    ret->type = OBJECT;
    ret->js_object_name = NULL;
    ret->js_str_value = NULL;
    ret->js_number_value = 0;
    ret->js_bool_value = 0;

    /* Close off list */
    ret->js_next = ret->js_child = NULL;

    return ret;

}

json_t *
json_new_string(char * val, char * key)
{

    json_t * ret = json_new();

    /* Set values */
    ret->type = JSTRING;
    ret->js_object_name = strdup(key);
	ret->js_str_value = json_escape_string(val);

    return ret;
}

/* ---------------------------------------------------------------- *
 * Free a json_t structure
 * ---------------------------------------------------------------- */

void
json_free(json_t * json)
{

    if (json == NULL)
        return;

    /* Free any children or siblings */
    if (json->js_child != NULL)
        json_free(json->js_child);
    if (json->js_next != NULL)
        json_free(json->js_next);

    /* Free any content */
    if (json->js_object_name != NULL)
        free(json->js_object_name);
    if (json->js_str_value != NULL)
        free(json->js_str_value);

	free(json);

}

/* ---------------------------------------------------------------- *
 * Some functions for manipulating JSON objects
 * ---------------------------------------------------------------- */


json_t *
json_get_item_by_key(json_t * obj, char * key) {

    json_t * i;
		
	/* Sanity check */

    if (obj == NULL || obj->type != OBJECT)
        return NULL;

    /* Find the item with the key */
    i = obj->js_child;
    while (i != NULL)
    {
        if (strcmp(i->js_object_name, key) == 0)
        {
            /* Got it */
            return i;
        }
        i = i->js_next;
    }

    return NULL;

}


/* ---------------------------------------------------------------- *
 * Parse a json_t Array
 * ---------------------------------------------------------------- */

size_t
json_skip_white_space(unsigned char * b, size_t i, size_t max)
{

    while (i < max && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n'))
        ++i;
        
    return i;

}

/* ---------------------------------------------------------------- *
 * Parse a json_t Array
 * ---------------------------------------------------------------- */

size_t
json_parse_array(unsigned char * b, size_t i,
				size_t max, json_t * ret)
{

    json_t * last = NULL;
    json_t * value = NULL;

    if (b[i] != '[') {
        // JSONParseArray entered on non '[' char
        return max;
    }
        
    /* Skep to next non white space char */
    i++;
    _JSON_CHECK_INDEX(i,max,max);
    i = json_skip_white_space(b,i,max);
    _JSON_CHECK_INDEX(i,max,max);

    while (i < max && b[i] != ']') {
        value = json_new();
        if (last == NULL)
            ret->js_child = value;
        else
            last->js_next = value;
        last = value;

        i = json_parse_value(b,i,max,value);
                
        /* Skip to next non-white */
        _JSON_CHECK_INDEX(i,max,max);
        i = json_skip_white_space(b,i,max);
        _JSON_CHECK_INDEX(i,max,max);
                
        if (b[i] == ']') {
            ++i;
            return i;
        }
                
        if (b[i] != ',') {
            // JSONParseArray expected ',' or '[' char
            return max;
        }

        ++i;

        /* Skip to next non-white */
        _JSON_CHECK_INDEX(i,max,max);
        i = json_skip_white_space(b,i,max);
        _JSON_CHECK_INDEX(i,max,max);
                
    }
        
    return ++i;
}

/* ---------------------------------------------------------------- *
 * Parse a json_t Value
 * ---------------------------------------------------------------- */

size_t
json_parse_value(unsigned char * b, size_t i,
size_t max, json_t * ret)
{

	if (b[i] == '{') {
		ret->type = OBJECT;
		/* Value is an Object */
		return json_parse_object(b, i, max, ret);
	}

	if (b[i] == '[') {
		/* Value is an Array */
		ret->type = ARRAY;
		return json_parse_array(b, i, max, ret);
	}

	if (b[i] == '"') {
		/* Value is a string */
		ret->type = JSTRING;
		return json_parse_string(b, i, max, &(ret->js_str_value));
	}

	if (strnicmp(&b[i], "false", 5) == 0) {
		/* Value is a boolean FALSE */
		ret->type = JFALSE;
		return i + 5;
	}

	if (strnicmp(&b[i], "true", 4) == 0) {
		/* Value is a boolean TRUE */
		ret->type = JTRUE;
		return i + 4;
	}
                
	if (strnicmp(&b[i], "null", 4) == 0) {
		/* Value is a boolean TRUE */
		ret->type = JNULL;
		return i + 4;
	}

	/* Unrecognised value - kill parse */
    return max;
}


/* ---------------------------------------------------------------- *
 * Parse a json_t String
 * ---------------------------------------------------------------- */


size_t
json_parse_string(unsigned char * b, size_t i,
				  size_t max, char ** ret) {
        
	size_t j;
	char * str;
        
    /* Should only get in here for a string */
    if (b[i] != '"') {
        return max;
    }
        
    /* Parse Value */
    ++i;
    _JSON_CHECK_INDEX(i,max,max);
    i = json_skip_white_space(b,i,max);
    _JSON_CHECK_INDEX(i,max,max);
        
    /* Find the closing '"' char */
    j = i;
    i = json_scan_for_char(b,i,max,'"');
    _JSON_CHECK_INDEX(i,max,max);
        
    /* Chars between those two points are the key */
    str = (char *) malloc (i - j + 1);
    memcpy(str, &b[j], i-j);
    str[i-j]='\0';
    *ret = str;

    /* Move off the closing '"' as we have consumed that */
    i++;
        
    return i;
}


/* ---------------------------------------------------------------- *
 * Parse a JSON Object
 * ---------------------------------------------------------------- */

size_t
json_parse_object(unsigned char * b, size_t i,
					size_t max, json_t * ret) {

    char * key;
    json_t * last = NULL;
    json_t * value = NULL;
        
    /* Can only get here if current char is '{'. If it isn't error 
     * out */

    if (b[i] != '{') {
        return max;
    }
        
    ++i;
    i = json_skip_white_space(b, i, max);
    _JSON_CHECK_INDEX(i,max,max);
        
    /* Looks like it might be valid JSON */
    while (i < max) {
        /* Loop through looking for key  */
        if (b[i] != '"')
            return max;
                        
        /* Parse key string */
        i = json_parse_string(b,i,max,&key);
                
        i = json_skip_white_space(b,i,max);
        _JSON_CHECK_INDEX(i,max,max);

        if (b[i] != ':') {
            // Expected ':' in JSON parse
            return max;
        }

        i++;
        i = json_skip_white_space(b,i,max);
        _JSON_CHECK_INDEX(i,max,max);
                
        /* this is now the value component of the object entry */
        /* set up the list */
        
        value = json_new();
        if (last == NULL)
        {
            ret->js_child = value;
        }
        else
        {
            last->js_next = value;
        }
        last = value;

        i = json_parse_value(b,i,max,value);
                                
        /* Add the key */
        value->js_object_name = key;
                
        /* Next should be a ',' or '}' char */
        i = json_skip_white_space(b,i,max);
        _JSON_CHECK_INDEX(i,max,max);
        if (b[i] == '}') {
            /* closes the object */
            return ++i;
        }
               
        if (b[i] != ',') {
            //JSON parse expected ',' or '}' char
            return max;
        }
        i++;
    }
        
    return i;
}



/* ---------------------------------------------------------------- *
 * Main call to parse a string into its JSON form
 * ---------------------------------------------------------------- */

json_t *
json_parse(unsigned char * b)
{
    size_t i = 0;    // Our current location in the string
    size_t max = strlen((char *) b); // maximum length of string

    /* Find the first non-white space character */
    i = json_skip_white_space(b, i, max);
    if (i >= max)
        return NULL;

    /* What are we working with here? */
    switch (b[i]) {
    case '{':
    {
        json_t * ret = json_new();
        ret->type = OBJECT;
        i = json_parse_object(b, i, max, ret);
        return ret;
    }
    default:
        break;
    }

    /* Should only get here on a bad error */
    return NULL;

}

/* ---------------------------------------------------------------- *
 * Create a string from the JSON input
 * ---------------------------------------------------------------- */

char *
json_append_str(char *b, char * a, size_t * sz) {

    char * ret;
    size_t bs, as;

    bs = strlen(b);
    as = strlen(a);

    if (bs + as >= *sz) {
        do {
            *sz = *sz * 2;
        }
        while (bs + as > *sz);

        ret = (char *) malloc (*sz);
        strcpy(ret, b);
        free (b);
    }
    else
        ret = b;

    return strcat(ret, a);

}

char *
json_to_string_array(json_t * json, char * str, size_t * sz)
{

    json_t * c;
    char * ret = str;

    if (json->type != ARRAY)
    {
        free (str);
        return NULL;
    }

    ret = json_append_str(str, "[", sz);

    c = json->js_child;

    while (c != NULL)
    {
        /* We have a series of values */
        ret = json_to_string_value(c, ret, sz);

        /* any more? */
        c = c->js_next;
        if (c != NULL)
            ret = json_append_str(ret, ",", sz);
    }

    return json_append_str(ret, "]", sz);

}

char *
json_to_string_value(json_t * json, char * str, size_t *sz)
{

    switch (json->type) {
    case(ARRAY):
        {
            return json_to_string_array(json, str, sz);
        }
    case (JSTRING):
        {
            char * ret = json_append_str(str, "\"", sz);
            ret = json_append_str(str, json->js_str_value, sz);
            return json_append_str(ret, "\"", sz);
        }
    case (NUMBER):
        {
            char n[128];
            _snprintf(n, 128, "%d", json->js_number_value);
            return json_append_str(str, n, sz);
        }
	case (OBJECT) :
		{
			return json_to_string_object(json, str, sz);
		}
    case (JTRUE):
        return json_append_str(str, "true", sz);
    case (JFALSE):
        return json_append_str(str, "false",sz);
    case (JNULL):
        return json_append_str(str, "NULL", sz);
    default:
        return str;
    }

    return str;

}

char *
json_to_string_object(json_t * json, char * str, size_t * sz)
{

    json_t * c;
    char * ret = str;

    if (json->type != OBJECT)
    {
        free (str);
        return NULL;
    }

    ret = json_append_str(str, "{", sz);

    c = json->js_child;

    while (c != NULL)
    {
        /* We have a series of key/value pairs */
		if (c->js_object_name != NULL)
		{
			ret = json_append_str(ret, "\"", sz);
			ret = json_append_str(ret, c->js_object_name, sz);
			ret = json_append_str(ret, "\"", sz);
			ret = json_append_str(ret, ":", sz);
		}
		ret = json_to_string_value(c, ret, sz);

        /* any more? */
        c = c->js_next;
        if (c != NULL)
            ret = json_append_str(ret, ",", sz);
    }

    return json_append_str(ret, "}", sz);

}


char *
json_to_string(json_t * json)
{

    char * ret;
    size_t sz = 2048;    /* Start with a 2K buffer */

    if (json->type != OBJECT)
        return NULL;

    ret = (char *) malloc (sz);
    ret[0] = '\0';

    return json_to_string_object(json, ret, &sz);

}

char *
json_escape_string(char * str)
{
	size_t i, sz;
	char * ret;

	/* Boundary conditions */
	if (str == NULL)
		return NULL;

	/* This is probably wasteful - but we calculate the final result size up front */
	i = 0;
	sz = 0;
	while (str[i] != '\0')
	{
		switch (str[i])
		{
		case '"':
		case '\\':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
			// This is an escape character so we escape it
			++sz;
			break;
		default:
			break;
		}

		++sz;
		++i;

	}

	if (sz == i)
		return strdup(str);

	/* We have something to escape */
	ret = (char *)malloc(sz + 1);
	i = 0;
	sz = 0;

	while (str[i] != '\0')
	{
		switch (str[i])
		{
		case '"' : ret[sz++] = '\\'; ret[sz++] = '"'; break;
		case '\\': ret[sz++] = '\\'; ret[sz++] = '\\'; break;
		case '\b': ret[sz++] = '\\'; ret[sz++] = 'b'; break;
		case '\f': ret[sz++] = '\\'; ret[sz++] = 'f'; break;
		case '\n': ret[sz++] = '\\'; ret[sz++] = 'n'; break;
		case '\r': ret[sz++] = '\\'; ret[sz++] = 'r'; break;
		case '\t': ret[sz++] = '\\'; ret[sz++] = 't'; break;
			break;
		default: ret[sz++] = str[i];
		}

		++i;

	}
	ret[sz] = '\0';

	return ret;


}

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

/*
* A wrapper for HTTP client code.  Like the crypto we use a pluggable module
* approach so we can switch operating systems without too much pain
*/

#ifndef AUTHME_HTTPC_H
#define AUTHME_HTTPC_H

#ifndef WIN32
#	include "config.h"
#endif

#include "service.h"
#include "utils.h"

#include <stdio.h>

/* Opaque type that the plugins can use to pass info */
typedef void * httpc_handle;

/* Function definitions */

typedef authme_err_t
(HTTPC_CREATE_CLIENT)(char * url, httpc_handle *hh);
typedef authme_err_t
(HTTPC_SET_READ_BFR)(httpc_handle hh, bfr_t * read);
typedef authme_err_t
(HTTPC_SET_WRITE_BFR)(httpc_handle hh, bfr_t * write);
typedef void 
(HTTPC_DESTROY_CLIENT)(httpc_handle hh);
typedef authme_err_t
(HTTPC_EXECUTE)(httpc_handle hh);
typedef char *
(HTTPC_GET_ERROR_STRING)(httpc_handle hh);
typedef authme_err_t
(HTTPC_GET_LAST_RESPONSE_CODE)(httpc_handle hh, long * code);
typedef authme_err_t
(HTTPC_ADD_HEADER)(httpc_handle hh, char * header);
typedef authme_err_t
(HTTPC_READ_HEADER)(httpc_handle hh, char * header, bfr_t * write);

// Shutdown
typedef void
(HTTPC_SHUTDOWN)();

typedef struct HTTPC_FUNCTION_TABLE_S {
	HTTPC_CREATE_CLIENT				* create_client;
	HTTPC_SET_READ_BFR				* set_read_bfr;
	HTTPC_SET_WRITE_BFR				* set_write_bfr;
	HTTPC_DESTROY_CLIENT			* destroy_client;
	HTTPC_EXECUTE					* execute;
	HTTPC_GET_ERROR_STRING			* get_error_string;
	HTTPC_GET_LAST_RESPONSE_CODE	* get_last_response_code;
	HTTPC_ADD_HEADER				* add_header;
	HTTPC_READ_HEADER				* read_header;
	HTTPC_SHUTDOWN					* shutdown;
} httpc_function_table_t;

typedef httpc_function_table_t *
(HTTPC_INIT)();

/*
* Wrapper function definitions
*
*/

/* Module */

void
httpc_init(HTTPC_INIT * provider);
void
httpc_shutdown();

/* Module functions */

authme_err_t
httpc_create_client(char * url, httpc_handle * hh);

/* Defines the buffer to upload to the server.  Automatically switches client to PUT */
authme_err_t
httpc_set_read_bfr(httpc_handle hh, bfr_t * read);
authme_err_t
httpc_set_write_bfr(httpc_handle hh, bfr_t * write);
void 
httpc_destroy_client(httpc_handle hh);
authme_err_t
httpc_execute(httpc_handle hh);
char *
httpc_get_error_string(httpc_handle hh);
authme_err_t
httpc_get_last_response_code(httpc_handle hh, long * code);
authme_err_t
httpc_add_header(httpc_handle hh, char * header);
authme_err_t
httpc_read_header(httpc_handle hh, char * header, bfr_t * write);

// Shutdown
void
httpc_shutdown();
#endif

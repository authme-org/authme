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

/* This is provided mainly for *NIX but does work with Windows */

#ifndef WIN32
#	include "config.h"
#endif

#if defined HAVE_CURL

#ifndef AUTHME_HTTPC_CURL_H
#define AUTHME_HTTPC_CURL_H

#include "service.h"
#include "httpc.h"

#include <curl/curl.h>

/*
* Master Password configuration
*
*/

typedef struct header_read_info {

	char * header;
	bfr_t * output;

} header_read_info_t;

typedef struct authme_httpc_curl_s {

	CURL				* ahc_curl;				/* Kinda obvious */
	bfr_t				* ahc_read_bfr;			/* This is what the client reads from to send to the server */
	bfr_t				* ahc_write_bfr;		/* This is what the client writes to with data from the server */
	struct curl_slist	* ahc_headers;			/* The list of headers to set on the client */
	header_read_info_t	* ahc_header_read_info;	/* Structure that holds all the data for header reading */
	char				* ahc_err_msg;

} authme_httpc_curl_t, * authme_httpc_curl_p;

/* Initialisation */
httpc_function_table_t *
httpc_curl_init();

void
httpc_curl_shutdown();

/* Module functions */

authme_err_t
httpc_curl_create_client(char * url, httpc_handle * hh);
authme_err_t
httpc_curl_set_read_bfr(httpc_handle hh, bfr_t * read);
authme_err_t
httpc_curl_set_write_bfr(httpc_handle hh, bfr_t * write);
void
httpc_curl_destroy_client(httpc_handle hh);
authme_err_t
httpc_curl_execute(httpc_handle hh);
char *
httpc_curl_get_error_string(httpc_handle hh);
authme_err_t
httpc_curl_get_last_response_code(httpc_handle hh, long * code);
authme_err_t
httpc_curl_add_header(httpc_handle hh, char * header);

/* When loading the page - get the header defined and write it into the bfr */
authme_err_t
httpc_curl_read_header(httpc_handle hh, char * header, bfr_t * write);

// Shutdown
void
httpc_shutdown();

#endif /* HTTPC_CURL_H */
#endif /* HAVE_CURL */

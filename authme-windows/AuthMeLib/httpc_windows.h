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

#if defined HAVE_WINHTTP

#ifndef AUTHME_HTTPC_WINDOWS_H
#define AUTHME_HTTPC_WINDOWS_H

#ifndef WIN32
#	include "config.h"
#endif

#include "service.h"
#include "httpc.h"

#include "stdafx.h"

#include <winhttp.h>

#pragma comment(lib, "winhttp")

/*
* Master Password configuration
*
*/

typedef struct header_read_info {

	PWSTR   header;
	bfr_t * output;

} header_read_info_t;

typedef struct authme_httpc_windows_s {

	HINTERNET			  ahw_hsession;			/* handle to the Windows HTTP session */
	HINTERNET			  ahw_hconnect;			/* handle to the Windows HTTP server connection */
	HINTERNET			  ahw_hrequest;			/* handle to the Windows HTTP request */
	URL_COMPONENTS		  ahw_url_components;	/* We keep the cracked URL around */
	PWSTR				  ahw_wurl;				/* Wide charater version of the URL */
	PWSTR				  ahw_hostname;			/* Hostname we are connecting to */
	bfr_t				* ahw_read_bfr;			/* This is what the client reads from to send to the server */
	bfr_t				* ahw_write_bfr;		/* This is what the client writes to with data from the server */
	PWSTR				  ahw_headers;			/* The list of headers to set on the client */
	header_read_info_t	* ahw_header_read_info;	/* Structure that holds all the data for header reading */
	char				* ahw_err_msg;

} authme_httpc_windows_t, *authme_httpc_windows_p;

/* Initialisation */
httpc_function_table_t *
httpc_windows_init();

void
httpc_windows_shutdown();

/* Module functions */

authme_err_t
httpc_windows_create_client(char * url, httpc_handle * hh);
authme_err_t
httpc_windows_set_read_bfr(httpc_handle hh, bfr_t * read);
authme_err_t
httpc_windows_set_write_bfr(httpc_handle hh, bfr_t * write);
void
httpc_windows_destroy_client(httpc_handle hh);
authme_err_t
httpc_windows_execute(httpc_handle hh);
char *
httpc_windows_get_error_string(httpc_handle hh);
authme_err_t
httpc_windows_get_last_response_code(httpc_handle hh, long * code);
authme_err_t
httpc_windows_add_header(httpc_handle hh, char * header);

/* When loading the page - get the header defined and write it into the bfr */
authme_err_t
httpc_windows_read_header(httpc_handle hh, char * header, bfr_t * write);

// Shutdown
void
httpc_shutdown();

#endif /* HTTPC_WINDOWS_H */
#endif /* HAVE_WINHTTP */
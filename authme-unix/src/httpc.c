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

#include "httpc.h"

#include <stdlib.h>

/*
* Global function table - intialised at startup
*/

httpc_function_table_t * HTTPC_FUNCTIONS = NULL;

/* For defaults */
#if defined HAVE_CURL
/* Default for now */
httpc_function_table_t * httpc_curl_init();
#endif

#if defined HAVE_WINHTTP
httpc_function_table_t * httpc_windows_init();
#endif

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */

/* Initialise the function table */

void
httpc_init(HTTPC_INIT * provider) {

	/* TODO: Remove defaults*/
	if (provider != NULL)
		HTTPC_FUNCTIONS = (provider)();

#if defined HAVE_CURL
	HTTPC_FUNCTIONS = httpc_curl_init();
#else
#if defined HAVE_WINHTTP
	HTTPC_FUNCTIONS = httpc_windows_init();
#endif
#endif
}

void
httpc_shutdown() {

	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->shutdown == NULL)
		return;

	(HTTPC_FUNCTIONS->shutdown)();

	free(HTTPC_FUNCTIONS);
	HTTPC_FUNCTIONS = NULL;

}

/* ---------------------------------------------------------------- *
* Function maps
* ---------------------------------------------------------------- */

authme_err_t
httpc_create_client(char * url, httpc_handle * hh)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->create_client == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->create_client)(url, hh);

}

authme_err_t
httpc_set_read_bfr(httpc_handle hh, bfr_t * read)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->set_read_bfr == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->set_read_bfr)(hh, read);

}

authme_err_t
httpc_set_write_bfr(httpc_handle hh, bfr_t * write)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->set_write_bfr == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->set_write_bfr)(hh, write);

}

void
httpc_destroy_client(httpc_handle hh)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->destroy_client == NULL)
		return;

	(HTTPC_FUNCTIONS->destroy_client)(hh);

}

authme_err_t
httpc_execute(httpc_handle hh)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->execute == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->execute)(hh);

}

char *
httpc_get_error_string(httpc_handle hh)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->get_error_string == NULL)
		return NULL;

	return (HTTPC_FUNCTIONS->get_error_string)(hh);

}

authme_err_t
httpc_get_last_response_code(httpc_handle hh, long * code) {

	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->get_last_response_code == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->get_last_response_code)(hh, code);
}

authme_err_t
httpc_add_header(httpc_handle hh, char * header) 
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->add_header == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->add_header)(hh, header);

}

authme_err_t
httpc_read_header(httpc_handle hh, char * header, bfr_t * write)
{
	if (HTTPC_FUNCTIONS == NULL || HTTPC_FUNCTIONS->read_header == NULL)
		return AUTHME_ERR_NO_HTTPC;

	return (HTTPC_FUNCTIONS->read_header)(hh, header, write);

}


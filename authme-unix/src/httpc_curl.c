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

#ifndef WIN32
#	include "config.h"
#else
#	include "stdafx.h"
#	include "AuthMeWindows.h"
#endif

/* Only compile this if curl is available */
#if defined HAVE_CURL

#include "httpc_curl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/* ---------------------------------------------------------------- *
* Error string handling
* ---------------------------------------------------------------- */

char * httpc_curl_get_error_string(httpc_handle hh) { return ((authme_httpc_curl_t *)hh)->ahc_err_msg; }
#define HTTPC_SET_ERROR(X,Y) {if (X->ahc_err_msg != NULL) {free (X->ahc_err_msg) ;} X->ahc_err_msg = strdup(Y); }

/* ---------------------------------------------------------------- *
* Curl helper functions
* ---------------------------------------------------------------- */

size_t
httpc_curl_write_bfr_fn(void * ptr, size_t size, size_t nmemb, void *userdata) {

	char * bf;

	bf = (char *)malloc((nmemb * size) + 1);
	memcpy(bf, ptr, (nmemb * size));
	bf[nmemb * size] = '\0';

	/* Now append to our data */
	append_bfr((bfr_t *)userdata, bf);

	return size * nmemb;

}

size_t
httpc_curl_read_bfr_fn(void *ptr, size_t size, size_t nmemb, void *userdata) {

	bfr_t * b = (bfr_t *)userdata;

	size_t sz = strlen(b->b) - b->i;

	if (sz == 0)
		/* Read complete */
		return 0;

	if (sz > (size * nmemb))
		sz = size * nmemb;

	memcpy(ptr, &((b->b)[b->i]), sz);
	b->i += sz;

	return sz;

}

size_t
httpc_curl_read_header_fn(void *ptr, size_t size, size_t nmemb, void *userdata)
{

	header_read_info_t * info = (header_read_info_t *)userdata;
	bfr_t * hdr = info->output;
	char * cptr = (char *)ptr;

	size_t sz = size * nmemb;

	/* Don't action unless it's worth it */
	if (sz <= 10)
		return sz;

	char * buf = (char *)malloc(sz + 1);
	memcpy(buf, ptr, sz);
	buf[sz] = '\0';

	/* Is this the Location Header? */
#ifdef WIN32
	if (strnicmp(ptr, info->header, strlen(info->header)) == 0) {
#else
	if (strncasecmp(ptr, info->header, strlen(info->header)) == 0) {
#endif

		size_t i;
		for (i = 0; cptr[i] != ':'; ++i);
		++i;
		while (cptr[i] == ' ' && i < sz)
			++i;

		if (i == sz)
			return sz;

		/* Copy into our buffer */
		check_bfr(hdr, sz);
		memcpy(hdr->b, &cptr[i], sz - i);
		/* Find end of string */
		size_t j;
		for (j = 0; j + i < sz; ++j)
		{
			if (hdr->b[j] == '\0' ||
				hdr->b[j] == ' ' ||
				hdr->b[j] == '\t' ||
				hdr->b[j] == '\r' ||
				hdr->b[j] == '\n')
				break;
		}

		hdr->b[j] = '\0';

	}

	return sz;

	}

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */

httpc_function_table_t *
httpc_curl_init()
{
	httpc_function_table_t * ret;

	/* Now create the function mapping table */
	ret = (httpc_function_table_t *)malloc(sizeof(httpc_function_table_t));
	memset(ret, 0, sizeof(httpc_function_table_t));

	/* Map in the OpenSSL functions */
	ret->create_client = httpc_curl_create_client;
	ret->destroy_client = httpc_curl_destroy_client;
	ret->set_read_bfr = httpc_curl_set_read_bfr;
	ret->set_write_bfr = httpc_curl_set_write_bfr;
	ret->shutdown = httpc_curl_shutdown;
	ret->execute = httpc_curl_execute;
	ret->get_error_string = httpc_curl_get_error_string;
	ret->get_last_response_code = httpc_curl_get_last_response_code;
	ret->add_header = httpc_curl_add_header;
	ret->read_header = httpc_curl_read_header;

	return ret;
}

void
httpc_curl_shutdown()
{
	/* Empty for now */
	return;
}

/* ---------------------------------------------------------------- *
* Create or destroy client
* ---------------------------------------------------------------- */

authme_err_t
httpc_curl_create_client(char * url, httpc_handle * hh) {

	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *)malloc(sizeof(authme_httpc_curl_t));
	memset(ahc, 0, sizeof(authme_httpc_curl_t));

	ahc->ahc_curl = curl_easy_init();

	if (!ahc->ahc_curl)
	{
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	*hh = ahc;
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_URL, url);

	return AUTHME_ERR_OK;

}

void
httpc_curl_destroy_client(httpc_handle hh) {

	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *)hh;

	if (ahc == NULL)
		return;

	if (ahc->ahc_headers != NULL)
	{
		curl_slist_free_all(ahc->ahc_headers);
		ahc->ahc_headers = NULL;
	}

	if (ahc->ahc_curl != NULL)
	{
		curl_easy_cleanup(ahc->ahc_curl);
		ahc->ahc_curl = NULL;
	}

	if (ahc->ahc_err_msg != NULL)
	{
		free(ahc->ahc_err_msg);
		ahc->ahc_err_msg = NULL;
	}

	if (ahc->ahc_header_read_info != NULL)
	{
		if (ahc->ahc_header_read_info->header != NULL)
		{
			free(ahc->ahc_header_read_info->header);
			ahc->ahc_header_read_info->header = NULL;
		}

		free(ahc->ahc_header_read_info);
		ahc->ahc_header_read_info = NULL;
	}

	free(ahc);

	return ;
}

/* ---------------------------------------------------------------- *
* Property handling
* ---------------------------------------------------------------- */

authme_err_t
httpc_curl_set_read_bfr(httpc_handle hh, bfr_t * read) {

	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *)hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	/* Because we have something to read from - we must be uploading data */
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_READFUNCTION, httpc_curl_read_bfr_fn);
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_READDATA, (void *)read);
	ahc->ahc_read_bfr = read;
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_INFILESIZE,
		(long)strlen(read->b));

	return AUTHME_ERR_OK;

}


authme_err_t
httpc_curl_set_write_bfr(httpc_handle hh, bfr_t * write) {

	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *) hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	ahc->ahc_write_bfr = write;

	/* Tell curl to write to this buffer*/
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_WRITEFUNCTION,
		httpc_curl_write_bfr_fn);
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_WRITEDATA, (void *)write);

	return AUTHME_ERR_OK;
}

authme_err_t
httpc_curl_get_last_response_code(httpc_handle hh, long * code)
{
	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *)hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	curl_easy_getinfo(ahc->ahc_curl, CURLINFO_RESPONSE_CODE, code);

	return AUTHME_ERR_OK;
}

authme_err_t
httpc_curl_add_header(httpc_handle hh, char * header)
{
	authme_httpc_curl_t * ahc;

	ahc = (authme_httpc_curl_t *)hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	ahc->ahc_headers = curl_slist_append(ahc->ahc_headers, header);

	return AUTHME_ERR_OK;
}

authme_err_t
httpc_curl_read_header(httpc_handle hh, char * header, bfr_t * write)
{
	authme_httpc_curl_t * ahc;
	header_read_info_t * hri;

	ahc = (authme_httpc_curl_t *)hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	hri = (header_read_info_t *)malloc(sizeof(header_read_info_t));
	hri->header = strdup(header);
	hri->output = write;
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_HEADERFUNCTION, httpc_curl_read_header_fn);
	curl_easy_setopt(ahc->ahc_curl, CURLOPT_WRITEHEADER, (void *)hri);

	ahc->ahc_header_read_info = hri;

	return AUTHME_ERR_OK;
}

/* ---------------------------------------------------------------- *
* Perform
* ---------------------------------------------------------------- */

authme_err_t
httpc_curl_execute(httpc_handle hh) {

	authme_httpc_curl_t * ahc;
	CURLcode res;

	ahc = (authme_httpc_curl_t *)hh;
	if (ahc == NULL || ahc->ahc_curl == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	/* Have we added any headers? */
	if (ahc->ahc_headers != NULL)
		curl_easy_setopt(ahc->ahc_curl, CURLOPT_HTTPHEADER, ahc->ahc_headers);

	res = curl_easy_perform(ahc->ahc_curl);

	if (res != CURLE_OK)
	{
		HTTPC_SET_ERROR(ahc, curl_easy_strerror(res));
		return AUTHME_ERR_HTTPC_CONNECT;
	}

	return AUTHME_ERR_OK;
}


#endif

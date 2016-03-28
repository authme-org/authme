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

/* Only compile this if Windows HTTP is available */
#if defined HAVE_WINHTTP

#ifndef WIN32
#	include "config.h"
#else
#	include "stdafx.h"
#	include "AuthMeWindows.h"
#endif

#include "httpc_windows.h"

#include <wchar.h>

PWSTR HTTP_VERB_GET = L"GET";
PWSTR HTTP_VERB_PUT = L"PUT";

/* ---------------------------------------------------------------- *
* Error string handling
* ---------------------------------------------------------------- */

char * httpc_windows_get_error_string(httpc_handle hh) { return ((authme_httpc_windows_t *)hh)->ahw_err_msg; }
#define HTTPC_SET_ERROR(X,Y) {if (X->ahw_err_msg != NULL) {free (X->ahw_err_msg) ;} X->ahw_err_msg = strdup(Y); }

/* ---------------------------------------------------------------- *
* parse for a particular header
* ---------------------------------------------------------------- */

int httpc_check_header(PWSTR ptr, header_read_info_t * info)
{

	size_t header_len;
	size_t sz;

	header_len = wcslen(info->header);
	sz = wcslen(ptr);

	/* Is this the header we are after? */
	if (wcsnicmp(ptr, info->header, header_len) == 0) 
	{

		size_t i, j;
		char * cbuf;

		for (i = 0; i < sz && ptr[i] != ':' && ptr[i] != '\r'; ++i);
		if (ptr[i] == '\r')
			return 0;

		++i;

		while (i < sz && ptr[i] == ' ')
			++i;

		if (i >= sz)
			return 0;

		/* Now find the terminator */
		j = i;
		for (j = i; j < sz; ++j)
		{
			if (ptr[j] == '\0' ||
				ptr[j] == ' ' ||
				ptr[j] == '\t' ||
				ptr[j] == '\r' ||
				ptr[j] == '\n')
				break;
		}

		cbuf = wStrToStrDupN(&ptr[i], j - i);
		if (cbuf == NULL)
			return 0;

		append_bfr(info->output, cbuf);
		free(cbuf);

		return 1;

	}

	return 0;

}

void httpc_windows_scan_headers(authme_httpc_windows_t * ahw, PWSTR headers)
{

	header_read_info_t * info;
	size_t i, sz;

	if ((info = ahw->ahw_header_read_info) == NULL)
		return;

	/* Loop through each one looking for our header */
	i = 0;
	sz = wcslen(headers);

	while (i != sz)
	{
		/* We are on the start of a header - check it */
		if (httpc_check_header(&headers[i], info))
		{
			// Done
			return;
		}

		/* Scan to end of current header */
		while (i < sz && headers[i] != '\r' && headers[i] != '\n')
			++i;

		/* Scan over the terminating characters */
		while (i < sz && (headers[i] == '\r' || headers[i] == '\n'))
			++i;
	}

}

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */

httpc_function_table_t *
httpc_windows_init()
{
	httpc_function_table_t * ret;

	/* Now create the function mapping table */
	ret = (httpc_function_table_t *)malloc(sizeof(httpc_function_table_t));
	memset(ret, 0, sizeof(httpc_function_table_t));

	/* Map in the OpenSSL functions */
	ret->create_client = httpc_windows_create_client;
	ret->destroy_client = httpc_windows_destroy_client;
	ret->set_read_bfr = httpc_windows_set_read_bfr;
	ret->set_write_bfr = httpc_windows_set_write_bfr;
	ret->shutdown = httpc_windows_shutdown;
	ret->execute = httpc_windows_execute;
	ret->get_error_string = httpc_windows_get_error_string;
	ret->get_last_response_code = httpc_windows_get_last_response_code;
	ret->add_header = httpc_windows_add_header;
	ret->read_header = httpc_windows_read_header;

	return ret;
}

void
httpc_windows_shutdown()
{
	/* Empty for now */
	return;
}

/* ---------------------------------------------------------------- *
* Create or destroy client
* ---------------------------------------------------------------- */

authme_err_t
httpc_windows_create_client(char * url, httpc_handle * hh) {

	authme_httpc_windows_t * ahw;
	PWSTR wurl;
	PWSTR hostname;
	DWORD request_flags = 0;

	ahw = (authme_httpc_windows_t *)malloc(sizeof(authme_httpc_windows_t));
	memset(ahw, 0, sizeof(authme_httpc_windows_t));

	/* Crack the URL */
	ahw->ahw_url_components.dwStructSize = sizeof(URL_COMPONENTS);

	/* We need scheme, hostname and full pathc */
	ahw->ahw_url_components.dwSchemeLength = -1;
	ahw->ahw_url_components.dwHostNameLength = -1;
	ahw->ahw_url_components.dwUrlPathLength = -1;
	ahw->ahw_url_components.dwExtraInfoLength = -1;

	wurl = strToWStrDup(url);
	if (wurl == NULL)
	{
		free(ahw);
		return AUTHME_ERR_HTTPC_BAD_URL;
	}

	if (!WinHttpCrackUrl(wurl, (DWORD) wcslen(wurl), 0, &ahw->ahw_url_components))
	{
		free(ahw);
		free(wurl);
		return AUTHME_ERR_HTTPC_INIT;
	}

	/* Is this HTTPS? */
	if (ahw->ahw_url_components.nScheme == INTERNET_SCHEME_HTTPS)
		request_flags |= WINHTTP_FLAG_SECURE;

	/* get the hostname */
	hostname = (PWSTR)malloc(sizeof(wchar_t) * (1 + ahw->ahw_url_components.dwHostNameLength));
	memcpy(hostname, ahw->ahw_url_components.lpszHostName, sizeof(wchar_t) * ahw->ahw_url_components.dwHostNameLength);
	hostname[ahw->ahw_url_components.dwHostNameLength] = 0;

	/* Start the session */
	if ((ahw->ahw_hsession = WinHttpOpen(L"WinHTTP AuthMe/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)) == 0)
	{
		free(ahw);
		free(wurl);
		free(hostname);
		return AUTHME_ERR_HTTPC_CONNECT;
	}

	if ((ahw->ahw_hconnect = WinHttpConnect(ahw->ahw_hsession, hostname, ahw->ahw_url_components.nPort, 0)) == 0)
	{
		WinHttpCloseHandle(ahw->ahw_hsession);
		free(ahw);
		free(wurl);
		free(hostname);
		return AUTHME_ERR_HTTPC_CONNECT;
	}

	ahw->ahw_wurl = wurl;
	ahw->ahw_hostname = hostname;
	ahw->ahw_headers = WINHTTP_NO_ADDITIONAL_HEADERS;

	*hh = ahw;

	return AUTHME_ERR_OK;

}

void
httpc_windows_destroy_client(httpc_handle hh) {

	authme_httpc_windows_t * ahw;

	ahw = (authme_httpc_windows_t *)hh;

	if (ahw == NULL)
		return;

	/* Close handles */
	if (ahw->ahw_hrequest)
		WinHttpCloseHandle(ahw->ahw_hrequest);

	if (ahw->ahw_hconnect)
		WinHttpCloseHandle(ahw->ahw_hconnect);

	if (ahw->ahw_hsession)
		WinHttpCloseHandle(ahw->ahw_hsession);

	/* Delete strings */
	if (ahw->ahw_err_msg != NULL)
		free(ahw->ahw_err_msg);

	if (ahw->ahw_headers != NULL)
		free(ahw->ahw_headers);

	if (ahw->ahw_header_read_info != NULL)
	{
		if (ahw->ahw_header_read_info->header != NULL)
			free(ahw->ahw_header_read_info->header);

		free(ahw->ahw_header_read_info);
	}

	if (ahw->ahw_hostname != NULL)
		free(ahw->ahw_hostname);

	if (ahw->ahw_wurl != NULL)
		free(ahw->ahw_wurl);

	memset(ahw, 0, sizeof(authme_httpc_windows_t));

	free(ahw);

	return;
}

/* ---------------------------------------------------------------- *
* Property handling
* ---------------------------------------------------------------- */

authme_err_t
httpc_windows_set_read_bfr(httpc_handle hh, bfr_t * read) {

	authme_httpc_windows_t * ahw;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hconnect == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	/* Because we have something to read from - we must be uploading data */
	ahw->ahw_read_bfr = read;

	return AUTHME_ERR_OK;

}


authme_err_t
httpc_windows_set_write_bfr(httpc_handle hh, bfr_t * write) {

	authme_httpc_windows_t * ahw;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hconnect == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	ahw->ahw_write_bfr = write;

	return AUTHME_ERR_OK;

}

authme_err_t
httpc_windows_get_last_response_code(httpc_handle hh, long * code)
{

	authme_httpc_windows_t * ahw;
	DWORD status_code;
	DWORD sz;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hrequest == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	sz = sizeof(DWORD);
	if (!WinHttpQueryHeaders(ahw->ahw_hrequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &sz, WINHTTP_NO_HEADER_INDEX))
	{
		HTTPC_SET_ERROR(ahw, "Unable to retreieve status code from HREQUEST handle");
		return AUTHME_ERR_HTTPC_OPERATION;
	}

	*code = status_code;

	return AUTHME_ERR_OK;
}

authme_err_t
httpc_windows_add_header(httpc_handle hh, char * header)
{
	authme_httpc_windows_t * ahw;
	PWSTR wheader;
	DWORD sz;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hconnect == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	wheader = strToWStrDup(header);

	/* Calculate the characters to send */
	sz = 0;
	if (ahw->ahw_headers == NULL)
	{
		ahw->ahw_headers = wheader;
	}
	else
	{
		PWSTR buf;
		sz = (DWORD)(wcslen(wheader) + wcslen(ahw->ahw_headers) + 3);
		buf = (PWSTR)malloc(sz * sizeof(wchar_t));
		swprintf(buf, sz, L"%s\r\n%s", ahw->ahw_headers, wheader);
		free(ahw->ahw_headers);
		ahw->ahw_headers = buf;
	}

	return AUTHME_ERR_OK;
}

authme_err_t
httpc_windows_read_header(httpc_handle hh, char * header, bfr_t * write)
{
	authme_httpc_windows_t * ahw;
	header_read_info_t * hri;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hconnect == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	hri = (header_read_info_t *)malloc(sizeof(header_read_info_t));
	hri->header = strToWStrDup(header);
	hri->output = write;

	ahw->ahw_header_read_info = hri;

	return AUTHME_ERR_OK;
}

/* ---------------------------------------------------------------- *
* Perform
* ---------------------------------------------------------------- */

authme_err_t
httpc_windows_execute(httpc_handle hh) {

	authme_httpc_windows_t * ahw;
	PWSTR verb;
	DWORD sz;
	PWSTR wbuf;

	ahw = (authme_httpc_windows_t *)hh;
	if (ahw == NULL || ahw->ahw_hconnect == NULL)
		return AUTHME_ERR_HTTPC_NO_INIT;

	/* We can now work out put vs. get */
	if (ahw->ahw_read_bfr != NULL)
	{
		verb = HTTP_VERB_PUT;
	}
	else
	{
		verb = HTTP_VERB_GET;
	}

	/* Open the request */
	ahw->ahw_hrequest = WinHttpOpenRequest(ahw->ahw_hconnect, verb, ahw->ahw_url_components.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	/* Send the request - we're good to go! */
	sz = ahw->ahw_read_bfr != NULL ? (DWORD) strlen(ahw->ahw_read_bfr->b) : 0;
	if (!WinHttpSendRequest(ahw->ahw_hrequest, ahw->ahw_headers, -1, WINHTTP_NO_REQUEST_DATA, 0, sz, 0))
	{
		HTTPC_SET_ERROR(ahw, "Error sending request");
		return AUTHME_ERR_HTTPC_CONNECT;
	}

	/* Do we have data to send? */
	if (ahw->ahw_read_bfr != NULL)
	{
		if (!WinHttpWriteData(ahw->ahw_hrequest, ahw->ahw_read_bfr->b, (DWORD)strlen(ahw->ahw_read_bfr->b), &sz))
		{
			DWORD error = GetLastError();
			HTTPC_SET_ERROR(ahw, "Error sending data");
			return AUTHME_ERR_HTTPC_OPERATION;
		}
	}

	/* Add now finish it up */
	if (!WinHttpReceiveResponse(ahw->ahw_hrequest, NULL))
	{
		HTTPC_SET_ERROR(ahw, "Error receiving response from server");
		return AUTHME_ERR_HTTPC_CONNECT;
	}

	/* Load headers if we need them */
	if (ahw->ahw_header_read_info != NULL)
	{
		sz = 0;
		WinHttpQueryHeaders(ahw->ahw_hrequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &sz, WINHTTP_NO_HEADER_INDEX);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			HTTPC_SET_ERROR(ahw, "Error finding size of headers");
			return AUTHME_ERR_HTTPC_CONNECT;
		}

		wbuf = (PWSTR)malloc(sz + 2);

		if (!WinHttpQueryHeaders(ahw->ahw_hrequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, wbuf, &sz, WINHTTP_NO_HEADER_INDEX))
		{
			HTTPC_SET_ERROR(ahw, "Error loading headers");
			return AUTHME_ERR_HTTPC_CONNECT;
		}

		httpc_windows_scan_headers(ahw, wbuf);
		free(wbuf);

	}

	/* get any data */
	if (ahw->ahw_write_bfr != NULL)
	{
		
		do
		{

			DWORD read = 0;
			char * buf;

			sz = 0;
			if (!WinHttpQueryDataAvailable(ahw->ahw_hrequest, &sz))
			{
				HTTPC_SET_ERROR(ahw, "Error requesting read of data");
				return AUTHME_ERR_HTTPC_OPERATION;
			}

			buf = (char *)malloc(sz + 1);
			memset(buf, 0, sz + 1);

			if (!WinHttpReadData(ahw->ahw_hrequest, buf, sz, &read))
			{
				HTTPC_SET_ERROR(ahw, "Error reading data");
				return AUTHME_ERR_HTTPC_OPERATION;
			}

			append_bfr(ahw->ahw_write_bfr, buf);
			free(buf);

		} while (sz > 0);
	}

	return AUTHME_ERR_OK;

}


#endif
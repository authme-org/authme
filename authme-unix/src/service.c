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

#include "service.h"

#ifndef WIN32
#	include "config.h"
#	include <syslog.h>
#	include <pwd.h>
#else
#	include "stdafx.h"
#endif

#include "json.h"
#include "utils.h"
#include "mpass.h"
#include "httpc.h"

#include <sys/types.h>

#include <string.h>
#include <stdlib.h>

 /* ---------------------------------------------------------------- *
 * Some system constants
 * ---------------------------------------------------------------- */

// Identifier for a AuthMe encrypted file
char magic_number[] = { 0x43, 0x35, 0x6F, 0x4d };

/* ---------------------------------------------------------------- *
* Initialisation and shutdown routines
* ---------------------------------------------------------------- */

authme_err_t
authme_service_init()
{
	mpass_init(NULL);
	httpc_init(NULL);
	return AUTHME_ERR_OK;
}

authme_err_t
authme_service_shutdown()
{
	mpass_shutdown();
	httpc_shutdown();
	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
 * authme_get_svc_check_status
 * ---------------------------------------------------------------- */

authme_err_t
authme_get_svc_check_status(authme_service_config_t * psc)
{

    /* Get the check status from the service */
	httpc_handle hh;
    long response_code;
    bfr_t * b;
    
    /* First build the URL if necessary */

    if (psc->psc_check_url == NULL) {
        size_t blen = strlen(psc->psc_check_id) +
            strlen(psc->psc_url) + strlen("/Check?checkId=");

        psc->psc_check_url = (char *) malloc (blen + 1);
        sprintf(psc->psc_check_url, "%s/Check?checkId=%s",
                psc->psc_url,
                psc->psc_check_id);
    }

    /* Now do the GET */
	if (httpc_create_client(psc->psc_check_url, &hh) != AUTHME_ERR_OK)
	{
		bfr_t * e = new_bfr();

		append_bfr(e, "Error connecting to service: ");
		append_bfr(e, "Cannot allocate curl handle");
		if (psc->psc_last_error != NULL)
			free(psc->psc_last_error);
		psc->psc_last_error = strdup(e->b);
		free_bfr(e);

		return AUTHME_ERR_SERVICE_CONNECT_FAILED;
	}
    b = new_bfr();

	httpc_set_write_bfr(hh, b);

    authme_err_t ret_code;

    if (httpc_execute(hh) != AUTHME_ERR_OK)
    {
        free_bfr(b);
        bfr_t * e = new_bfr();

        append_bfr(e, "Error connecting to service: ");
        append_bfr(e, httpc_get_error_string(hh));
        if (psc->psc_last_error != NULL)
            free(psc->psc_last_error);
        psc->psc_last_error = strdup(e->b);
        free_bfr(e);

        ret_code = AUTHME_ERR_SERVICE_CONNECT_FAILED;
    }
    
    /* Output */
	httpc_get_last_response_code(hh, &response_code);
   
	if (response_code == 200) {
		/* Find the actual status */
		json_t * json = json_parse(b->b);
		json_t * i = json_get_item_by_key(json, "status");
		if (i != NULL && i->type == JSTRING)
		{
			/* Check what the status is */
			ret_code = AUTHME_ERR_OK;
			if (strcmp("APPROVED", i->js_str_value) == 0)
				psc->psc_check_status = AUTHME_STATUS_APPROVED;
			else if (strcmp("DECLINED", i->js_str_value) == 0)
				psc->psc_check_status = AUTHME_STATUS_DECLINED;
			else if (strcmp("SUBMITTED", i->js_str_value) == 0)
				psc->psc_check_status = AUTHME_STATUS_SUBMITTED;
			else
			{
				char buf[128];
				psc->psc_check_status = AUTHME_STATUS_UNDEFINED;
				snprintf(buf, 127, "Unknown status from service: %s", i->js_str_value);
				psc->psc_last_error = strdup(buf);
				ret_code = AUTHME_ERR_SERVICE_ERROR;
			}

		}
		else {

			ret_code = AUTHME_ERR_SERVICE_ERROR;
		}

		/* Check to see if there is an unwrapped Secret */
		i = json_get_item_by_key(json, "unwrappedSecret");
		if (i != NULL && i->type == JSTRING && i->js_str_value != NULL && strlen(i->js_str_value) > 0)
		{
			unsigned char * unwrapped_secret;
			size_t unwrapped_secret_len;

			if (mpass_envelope_decrypt(psc->psc_mpass, MPASS_SERVICE_PRIVATE_KEY, i->js_str_value, &unwrapped_secret, &unwrapped_secret_len) == AUTHME_ERR_OK)
			{
				/* We found a secret */
				psc->psc_unwrapped_secret = unwrapped_secret;
				psc->psc_unwrapped_secret_len = unwrapped_secret_len;
			}

		}

		json_free(json);
	}
    else 
    {
        char buf[128];
        snprintf(buf, 128, "HTTP Error Code %d received from service", 
                 response_code);
        psc->psc_last_error = strdup(buf);
        ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
    }

	httpc_destroy_client(hh);
    free_bfr(b);

    return ret_code;
}

/* ---------------------------------------------------------------- *
* authme_set_shared_secret
* ---------------------------------------------------------------- */

authme_err_t
authme_wrap_secret(authme_service_config_t * psc, unsigned char * secret, size_t secret_len, char ** wrapped_secret)
{
	unsigned char * mpass_wrapped_buf, *user_wrapped_buf;
	size_t mpass_wrapped_buf_len, user_wrapped_buf_len;
	authme_err_t ret_code;
	unsigned char * encrypted_secret;

	// Wrap with our own key first
	ret_code = mpass_envelope_encrypt(psc->psc_mpass, MPASS_SERVICE_PUBLIC_KEY, secret, secret_len, &mpass_wrapped_buf, &mpass_wrapped_buf_len);

	if (ret_code != AUTHME_ERR_OK)
	{
		AUTHME_SET_ERROR(psc, mpass_get_error_string(psc->psc_mpass));
	}

	ret_code = mpass_envelope_encrypt(psc->psc_mpass, MPASS_USER_PUBLIC_KEY, mpass_wrapped_buf, mpass_wrapped_buf_len, &user_wrapped_buf, &user_wrapped_buf_len);
	free(mpass_wrapped_buf);

	if (ret_code != AUTHME_ERR_OK)
	{
		AUTHME_SET_ERROR(psc, mpass_get_error_string(psc->psc_mpass));
		return ret_code;
	}

	if (mpass_b64_encode(psc->psc_mpass, user_wrapped_buf, user_wrapped_buf_len, &encrypted_secret) != AUTHME_ERR_OK)
	{
		free(user_wrapped_buf);
		AUTHME_SET_ERROR(psc, "Error base64 encoding wrapped secret");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	free(user_wrapped_buf);
	*wrapped_secret = encrypted_secret;
	return AUTHME_ERR_OK;
}

authme_err_t 
authme_wrap_and_set_secret(authme_service_config_t * psc, unsigned char * secret, size_t secret_len)
{
	char * wrapped_secret;
	authme_err_t ret_code;

	if ((ret_code = authme_wrap_secret(psc, secret, secret_len, &wrapped_secret)) != AUTHME_ERR_OK)
		return ret_code;

	ret_code = authme_set_secret(psc, wrapped_secret);
	free(wrapped_secret);

	return ret_code;

}


authme_err_t
authme_encrypt_file(authme_service_config_t * psc, char * in_file, char * out_file, char local_key)
{
	unsigned char key[32];
	
	FILE * in, *out;
	authme_err_t ret_code;
	size_t len;
	char * wrapped_secret;

	/* Generate the AES 256 key */
	if ((ret_code = mpass_random_bytes(psc->psc_mpass, key, 32)) != AUTHME_ERR_OK)
		return ret_code;

	if ((in = fopen(in_file, "rb")) == NULL)
	{
		AUTHME_SET_ERROR(psc, "Unable to open input file");
		return AUTHME_ERR_INVALID_FILENAME;
	}

	if ((out = fopen(out_file, "wb")) == NULL)
	{
		AUTHME_SET_ERROR(psc, "Unable to open output file");
		return AUTHME_ERR_INVALID_FILENAME;
	}

	/* Magic number */
	fwrite(magic_number, sizeof(magic_number), 1, out);

	/* Wrap and set the key */
	if ((ret_code = authme_wrap_secret(psc, key, 32, &wrapped_secret)) != AUTHME_ERR_OK)
	{
		fclose(in);
		fclose(out);
		return ret_code;
	}

	if (local_key)
	{
		fputc(AUTHME_FILE_LOCAL_KEY, out);
		len = strlen(wrapped_secret);

		fputc(((len + 1) >> 8) & 0xFF, out);
		fputc((len + 1) & 0xFF, out);
		fwrite(wrapped_secret, sizeof(char), len + 1, out);
		free(wrapped_secret);
	}
	else
	{
		if ((ret_code = authme_set_secret(psc, wrapped_secret)) != AUTHME_ERR_OK)
		{
			fclose(in);
			fclose(out);
			free(wrapped_secret);
			return ret_code;
		}

		free(wrapped_secret);
		if (psc->psc_secret_id == NULL)
		{
			fclose(in);
			fclose(out);
			AUTHME_SET_ERROR(psc, "Unknown error storing key");
			return AUTHME_ERR_CRYPTO_OPERATION;
		}

		/* How is the encryption key stored? */
		fputc(AUTHME_FILE_SERVICE_KEY, out);

		/* Drop the key handle to the file */
		len = strlen(psc->psc_secret_id);
		if (len > 254)
		{
			// Out
			fclose(in);
			fclose(out);
			AUTHME_SET_ERROR(psc, "Unbelievable secret ID");
			return AUTHME_ERR_CRYPTO_OPERATION;

		}

		/* Key ID or key is stored as 2 bytes of length and then the string */
		// First put the length of the ID including \0 at end.  High order byte first

		fputc(((len + 1) >> 8) & 0xFF, out);
		fputc((len + 1) & 0xFF, out);
		fwrite(psc->psc_secret_id, sizeof(char), len + 1, out);

	}
	// Now we let the mpass module do the encrypt
	ret_code = mpass_encrypt_file_to_file(psc->psc_mpass, key, in, out);

	fclose(in);
	fclose(out);

	return ret_code;

}

authme_err_t
authme_decrypt_file(authme_service_config_t * psc, char * in_file, char * out_file)
{
	FILE * in, *out;
	authme_err_t ret_code;
	int len;
	char magic_read[4];
	char * key_buf;
	int c;
	int i;
	int encryption_type;

	if ((in = fopen(in_file, "rb")) == NULL)
	{
		AUTHME_SET_ERROR(psc, "Unable to open input file");
		return AUTHME_ERR_INVALID_FILENAME;
	}

	if ((out = fopen(out_file, "wb")) == NULL)
	{
		AUTHME_SET_ERROR(psc, "Unable to open output file");
		return AUTHME_ERR_INVALID_FILENAME;
	}

	/* Get the magic number */
	if (fread(magic_read, 4, 1, in) != 1)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Unable to read magic string from input file");
		return AUTHME_ERR_FILE_READ;
	}

	if (memcmp(magic_read, magic_number, 4) != 0)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Is this an AuthMe encrypted file?");
		return AUTHME_ERR_FILE_READ;
	}

	/* Get the encryption type */
	if ((encryption_type = getc(in)) == EOF)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Unable to read ID size from input file");
		return AUTHME_ERR_FILE_READ;
	}

	/* TODO - DO SOMETHING WITH THE ENCRYPTION TYPE */

	/* Find the size of the blob ID */
	len = 0;
	for (i = 0; i < 2; ++i)
	{
		len = len << 8;
		if ((c = getc(in)) == EOF || (c < 0) || (c > 256))
		{
			fclose(in);
			fclose(out);
			AUTHME_SET_ERROR(psc, "Unable to read ID size from input file");
			return AUTHME_ERR_FILE_READ;
		}
		len = len | (size_t) c;
	}

	if (len > 64000)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Rediculous key length");
		return AUTHME_ERR_FILE_READ;
	}

	key_buf = (char *)malloc((size_t)len);

	/* Read the ID and do a quick sanity check */
	if (fread(key_buf, 1, len, in) != len || key_buf[len-1] != '\0')
	{
		fclose(in);
		fclose(out);
		free(key_buf);
		AUTHME_SET_ERROR(psc, "Unable to read key data from input file");
		return AUTHME_ERR_FILE_READ;
	}

	/* Start up the request to the service */
	switch (encryption_type)
	{
	case (AUTHME_FILE_SERVICE_KEY) :
		psc->psc_secret_id = strdup(key_buf);
		break;
	case AUTHME_FILE_LOCAL_KEY:
		psc->psc_wrapped_secret = strdup(key_buf);
		break;
	default:
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Unknown key storage type");
		free(key_buf);
		return AUTHME_ERR_FILE_READ;
	}

	free(key_buf);
	if ((ret_code = authme_start_svc_check(psc)) != AUTHME_ERR_OK)
	{
		fclose(in);
		fclose(out);
		return ret_code;
	}

	/* Have the check started up - just iterate */
	for (i = 0; i < 60; ++i)
	{
		/* First sleep to let the user do something */
#if defined WIN32
		Sleep(1000);
#else
		sleep(1);
#endif

		/* Check the current status on the service */
		ret_code = authme_get_svc_check_status(psc);
		if (ret_code == AUTHME_ERR_OK)
		{
			if (psc->psc_check_status == AUTHME_STATUS_APPROVED)
			{
				// Exit the loop
				break;
			}
			if (psc->psc_check_status == AUTHME_STATUS_DECLINED) {
				fclose(in);
				fclose(out);
				AUTHME_SET_ERROR(psc, "Request to decrypt file was declined");
				return AUTHME_ERR_REQUEST_DECLINED;
			}
		}
		else {
			fclose(in);
			fclose(out);
			return ret_code;
		}
	}

	if (psc->psc_check_status != AUTHME_STATUS_APPROVED)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Timeout waiting for response to decrypt request");
		return AUTHME_ERR_TIMEOUT;
	}

	/* Did we get an unwrapped secret? Shouldn't actually happen */
	if (psc->psc_unwrapped_secret == NULL || psc->psc_unwrapped_secret_len != 32)
	{
		fclose(in);
		fclose(out);
		AUTHME_SET_ERROR(psc, "Encryption key for file not unwrapped by user or is incorrect length");
		return AUTHME_ERR_SERVICE_ERROR;
	}

	/* Now decrypt */
	ret_code = mpass_decrypt_file_from_file(psc->psc_mpass, psc->psc_unwrapped_secret, in, out);

	if (ret_code != AUTHME_ERR_OK)
	{
		psc->psc_last_error = strdup(mpass_get_error_string(psc->psc_mpass));
	}

	fclose(in);
	fclose(out);

	return ret_code;

}

authme_err_t
authme_set_secret(authme_service_config_t * psc, char * wrapped_secret)
{

	json_t * j, *i;
	char * put_buffer;
	bfr_t * b, * c, *url;
	httpc_handle(hh);
	long response_code;
	authme_err_t ret_code;

	/* Upload to service */
	j = json_new();
	j->type = OBJECT;

	j->js_child = json_new();
	j->js_child->type = ARRAY;
	j->js_child->js_object_name = strdup("blobs");

	i = j->js_child;
	i->js_child = json_new();

	i = i->js_child;
	i->type = OBJECT;

	/* Add the various required elements */
	i->js_child = json_new_string(psc->psc_user_key_id, "keyId");
	i = i->js_child;
	i->js_next = json_new_string("PUBLIC_KEY", "encryptionType");
	i = i->js_next;
	i->js_next = json_new_string(wrapped_secret, "base64Data");
	i = i->js_next;
	i->js_next = json_new_string("A-temp-ID-for-secret", "ownerId");
	i = i->js_next;

	/* Transform to text */
	put_buffer = json_to_string(j);

	/* Build URL */
	url = new_bfr();
	append_bfr(url, psc->psc_url);
	append_bfr(url, "/Blobs");

	/* Now send to service */
	if (httpc_create_client(url->b, &hh) != AUTHME_ERR_OK) {
		free_bfr(url);
		json_free(j);
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	b = new_bfr();
	c = new_bfr();
	append_bfr(b, put_buffer);
	b->i = 0;


	/* Set ContentType for JSON */
	httpc_add_header(hh, "Content-Type: application/json");

	/* Now set up the PUT */
	httpc_set_read_bfr(hh, b);
	httpc_set_write_bfr(hh, c);

	if (httpc_execute(hh) != AUTHME_ERR_OK)
	{
		bfr_t * e = new_bfr();

		append_bfr(e, "Error connecting to service: ");
		append_bfr(e, httpc_get_error_string(hh));
		psc->psc_last_error = strdup(e->b);

		free_bfr(e);
		free_bfr(c);
		free_bfr(b);
		json_free(j);

		ret_code = AUTHME_ERR_SERVICE_CONNECT_FAILED;
	}

	/* Output */
	httpc_get_last_response_code(hh, &response_code);

	ret_code = AUTHME_ERR_OK;
	if (response_code == 201) {

		/* Find the actual status */
		json_t * json = json_parse(c->b);
		json_t * i = json_get_item_by_key(json, "success");
		if (i != NULL && i->type == JTRUE)
		{
			if ((i = json_get_item_by_key(json, "blobUniqueIds")) != NULL &&
				i->type == ARRAY  &&
				i->js_child != NULL &&
				i->js_child->type == JSTRING)
			{
				/* Have a string to put into the return */
				psc->psc_secret_id = strdup(i->js_child->js_str_value);
			}
			else
			{
				psc->psc_last_error = strdup("Success but no IDs returned");
				ret_code = AUTHME_ERR_SERVICE_ERROR;
			}
		}
		else {
			psc->psc_last_error = strdup("Service returned false in success flag");
			ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
		}
	}

	else if (response_code == 404)
	{
		psc->psc_last_error = strdup("Unknown user passed to service");
		ret_code = AUTHME_ERR_USER_UNKNOWN;
	}
	else
	{

		char buf[128];
		snprintf(buf, 128, "HTTP Error Code %d received from service",
			response_code);
		psc->psc_last_error = strdup(buf);
		ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
	}

	httpc_destroy_client(hh);
	free_bfr(c);
	free_bfr(b);
	json_free(j);

	return ret_code;

}


/* ---------------------------------------------------------------- *
 * authme_start_svc_check
 * ---------------------------------------------------------------- */

/*
 * Starts a check on a given userID to the Authme service
 */

int
authme_start_svc_check(authme_service_config_t * psc)
{
	json_t * j, *i;
	char * put_buffer;
	bfr_t * b, *url, *hdr;
	long response_code;
	httpc_handle hh;

	/* Build the appropriate JSON structure */
	j = json_new();
	j->type = OBJECT;

	/* Add the various required elements */
	j->js_child = json_new_string(psc->psc_user_id, "userId");
	i = j->js_child;
	if (psc->psc_server_id != NULL)
	{
		i->js_next = json_new_string(psc->psc_server_id, "serverId");
		i = i->js_next;
	}
	i->js_next = json_new_string("RANDOM", "serverNonce");
	i = i->js_next;
	if (psc->psc_server_string)
	{
		i->js_next = json_new_string(psc->psc_server_string,
			"serverString");
		i = i->js_next;
	}

	if (psc->psc_wrapped_secret)
	{
		i->js_next = json_new_string(psc->psc_wrapped_secret,
			"wrappedSecret");
		i = i->js_next;
	}
	else if (psc->psc_secret_id)
	{
		i->js_next = json_new_string(psc->psc_secret_id,
			"secretId");
		i = i->js_next;
	}

	/* Transform to text */
	put_buffer = json_to_string(j);

	/* Clean up */
	json_free(j);

	/* Build URL */
	url = new_bfr();
	append_bfr(url, psc->psc_url);
	append_bfr(url, "/Check");

	/* Now send to service */
	if (httpc_create_client(url->b, &hh) != AUTHME_ERR_OK)
	{
		free_bfr(url);
		free(put_buffer);
		return AUTHME_ERR_HTTPC_INIT;
	}

	free_bfr(url);
	b = new_bfr();
	append_bfr(b, put_buffer);
	free(put_buffer);
	b->i = 0;


	/* Set ContentType for JSON */
	httpc_add_header(hh, "Content-Type: application/json");

	/* Now set up the PUT */
	httpc_set_read_bfr(hh, b);
	hdr = new_bfr();
	httpc_read_header(hh, "Location:", hdr);

	authme_err_t ret_code;

	if (httpc_execute(hh) != AUTHME_ERR_OK)
	{
		bfr_t * e = new_bfr();

		append_bfr(e, "Error connecting to service: ");
		append_bfr(e, httpc_get_error_string(hh));
		psc->psc_last_error = strdup(e->b);

		free_bfr(e);

		ret_code = AUTHME_ERR_SERVICE_CONNECT_FAILED;
	}

	/* Output */
	httpc_get_last_response_code(hh, &response_code);
	if (response_code == 201) {
		if (hdr->b[0] != '\0') {
			/* Find the check's URL and ID */
			size_t i;
			psc->psc_check_url = strdup(hdr->b);
			for (i = 0; psc->psc_check_url[i] != '=' &&
				psc->psc_check_url[i] != '\0'; ++i);

				if (psc->psc_check_url[i] == '=')
					psc->psc_check_id = strdup(&psc->psc_check_url[i + 1]);

			/* Set for status checks */
			psc->psc_check_status = AUTHME_STATUS_SUBMITTED;
			ret_code = AUTHME_ERR_OK;
		}
		else
		{
			psc->psc_last_error = strdup("Service call succeeded, but did not return a valid Check ID");
			ret_code = AUTHME_ERR_SERVICE_ERROR;
		}
	}

	else if (response_code == 404)
	{
		psc->psc_last_error = strdup("Unknown user passed to service");
		ret_code = AUTHME_ERR_USER_UNKNOWN;
	}
	else
	{

		char buf[128];
		snprintf(buf, 128, "HTTP Error Code %d received from service",
			response_code);
		psc->psc_last_error = strdup(buf);
		ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
	}

	free_bfr(hdr);
	free_bfr(b);
	httpc_destroy_client(hh);
	return ret_code;
}

/* ---------------------------------------------------------------- *
* authme_get_user_public_key
* ---------------------------------------------------------------- */

/*
* Just does a straight GET to the main service URL to obtain
* the public key of a user.
*
* Returns the Base64 encoded key - but doesn't tranform it into the
* crypto engine
*
* For testing use:
*
* "http://pluto:8080/AuthMeWS/Svc/UserPublicKey?userId=berin-test@wingsofhermes.org"
*/


authme_err_t
authme_get_user_public_key(authme_service_config_t * psc)
{

	httpc_handle hh;
	bfr_t *url, *b;
	long response_code;
	char * public_as_base64;

	/* Sanity checks */
	if (psc->psc_url == NULL || psc->psc_user_id == NULL)
	{
		psc->psc_last_error = strdup("Adding a secret requires service URL and UserId");
		return AUTHME_ERR_INVALID_PARMS;
	}


	/* Build URL */
	url = new_bfr();
	append_bfr(url, psc->psc_url);
	append_bfr(url, "/UserPublicKey?userId=");
	append_bfr(url, psc->psc_user_id);

	/* Now send to service */
	if (httpc_create_client(url->b, &hh) != AUTHME_ERR_OK)
	{
		free_bfr(url);
		return AUTHME_ERR_OUT_OF_MEMORY;
	}
	free_bfr(url);

	b = new_bfr();

	/* Do the GET */
	httpc_set_write_bfr(hh, b);

	authme_err_t ret_code = AUTHME_ERR_OK;

	if (httpc_execute(hh) != AUTHME_ERR_OK)
	{
		bfr_t * e = new_bfr();

		append_bfr(e, "Error connecting to service: ");
		append_bfr(e, httpc_get_error_string(hh));
		psc->psc_last_error = strdup(e->b);

		free_bfr(e);

		ret_code = AUTHME_ERR_SERVICE_CONNECT_FAILED;
	}
	else
	{

		/* Output */
		httpc_get_last_response_code(hh, &response_code);

		if (response_code == 200)
		{
			/* Find the actual status */
			json_t * json = json_parse(b->b);
			json_t * i = json_get_item_by_key(json, "success");
			if (i != NULL && i->type == JTRUE)
			{
				if ((i = json_get_item_by_key(json, "publicKey")) != NULL &&
					i->type == JSTRING)
				{
					/* Have a string to put into the return */
					public_as_base64 = strdup(i->js_str_value);
					ret_code = authme_load_user_public_key(psc, public_as_base64);
					free(public_as_base64);
				}
				else
				{
					psc->psc_last_error = strdup("Success but no server version returned");
					ret_code = AUTHME_ERR_SERVICE_ERROR;
				}

				if (ret_code == AUTHME_ERR_OK)
				{
					if (ret_code == AUTHME_ERR_OK && (i = json_get_item_by_key(json, "keyId")) != NULL &&
						i->type == JSTRING)
					{
						psc->psc_user_key_id = strdup(i->js_str_value);
					}
					else
					{
						psc->psc_last_error = strdup("Success but no server version returned");
						ret_code = AUTHME_ERR_SERVICE_ERROR;
					}
				}

			}
			else {
				psc->psc_last_error = strdup("Service returned false in success flag");
				ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
			}

			json_free(json);
		}
		else if (response_code == 404)
		{
			psc->psc_last_error = strdup("User unknown to service");
			return AUTHME_ERR_USER_UNKNOWN;
		}
		else
		{

			char buf[128];
			snprintf(buf, 128, "HTTP Error Code %d received from service",
				response_code);
			psc->psc_last_error = strdup(buf);
			ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
		}
	}

	httpc_destroy_client(hh);
	free_bfr(b);

	return ret_code;
}

/* ---------------------------------------------------------------- *
 * authme_get_svc_info
 * ---------------------------------------------------------------- */

/*
 * Just does a straight GET to the main service URL to obtain
 * basic service info.  Only used interactively
 *
 * For testing use:
 *
 * "http://pluto:8080/AuthMeWS/Svc"
 */

authme_err_t
authme_get_svc_info (authme_service_config_t * psc)
{

	httpc_handle hh;
	long response_code;
	bfr_t * b;
	authme_err_t aerr;
	authme_err_t ret_code = AUTHME_ERR_OK;

	/* Initialise the HTTPC */
	if (httpc_create_client(psc->psc_url, &hh) != AUTHME_ERR_OK)
		return AUTHME_ERR_HTTPC_INIT;

	b = new_bfr();

	if ((aerr = httpc_set_write_bfr(hh, b)) != AUTHME_ERR_OK)
	{
		httpc_destroy_client(hh);
		return aerr;
	}

	if (httpc_execute(hh) != AUTHME_ERR_OK)
	{
		bfr_t * e = new_bfr();

		append_bfr(e, "Error connecting to service: ");
		append_bfr(e, httpc_get_error_string(hh));
		psc->psc_last_error = strdup(e->b);

		free_bfr(e);

		ret_code = AUTHME_ERR_SERVICE_CONNECT_FAILED;

	}

	else
	{

		/* Output */
		response_code = 0;
		httpc_get_last_response_code(hh, &response_code);

		if (response_code == 200)
		{
			/* Find the actual status */
			json_t * json = json_parse(b->b);
			json_t * i = json_get_item_by_key(json, "success");
			if (i != NULL && i->type == JTRUE)
			{
				if ((i = json_get_item_by_key(json, "serverVersion")) != NULL &&
					i->type == JSTRING)
				{
					/* Have a string to put into the return */
					psc->psc_last_error = strdup(i->js_str_value);
					ret_code = AUTHME_ERR_OK;
				}
				else
				{
					psc->psc_last_error = strdup("Success but no server version returned");
					ret_code = AUTHME_ERR_SERVICE_ERROR;
				}

			}
			else {
				psc->psc_last_error = strdup("Service returned false in success flag");
				ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
			}

			json_free(json);
		}
		else
		{

			char buf[128];
			snprintf(buf, 128, "HTTP Error Code %d received from service",
				response_code);
			psc->psc_last_error = strdup(buf);
			ret_code = AUTHME_ERR_SERVICE_RETURNED_ERR;
		}
	}

	httpc_destroy_client(hh);
	free_bfr(b);

	return ret_code;
}

/* ---------------------------------------------------------------- *
 * Config manipulation
 * ---------------------------------------------------------------- */


authme_service_config_t * 
authme_service_config_create(void)
{

    authme_service_config_t * psc;

    psc = (authme_service_config_t *) 
        malloc (sizeof (authme_service_config_t));

	memset(psc, 0, sizeof(authme_service_config_t));

    psc->psc_url = NULL;
    psc->psc_check_url = NULL;
    psc->psc_check_id = NULL;
    psc->psc_user_id = NULL;
    psc->psc_nonce = NULL;
    psc->psc_server_id = NULL;
	psc->psc_secret_id = NULL;
    psc->psc_server_string = NULL;
    psc->psc_last_error = NULL;
    psc->psc_check_status = 0;
	psc->psc_unwrapped_secret = NULL;
	psc->psc_wrapped_secret = NULL;
	psc->psc_unwrapped_secret_len = 0;
	psc->psc_mpass = NULL;
	psc->psc_key_file = NULL; // get_default_key_file_name();
	psc->psc_key_file_pass.password_format = AUTHME_KEY_PASS_NONE;

    return psc;

}

#define _AUTHME_FREE_CONFIG_ITEM(p, x) {if (p->x != NULL) \
        {free(p->x); p->x = NULL;}}

void authme_service_config_free(authme_service_config_t * psc)
{

    if (psc == NULL)
        return;
	
    /* First any internal data */
    _AUTHME_FREE_CONFIG_ITEM(psc, psc_url);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_check_url);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_user_key_id);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_check_id);
    _AUTHME_FREE_CONFIG_ITEM(psc, psc_user_id);
    _AUTHME_FREE_CONFIG_ITEM(psc, psc_nonce);
    _AUTHME_FREE_CONFIG_ITEM(psc, psc_server_id);
    _AUTHME_FREE_CONFIG_ITEM(psc, psc_last_error);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_wrapped_secret);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_secret_id);
	_AUTHME_FREE_CONFIG_ITEM(psc, psc_key_file);

	if (psc->psc_key_file_pass.password_data != NULL)
	{
		free(psc->psc_key_file_pass.password_data);
		psc->psc_key_file_pass.password_format = AUTHME_KEY_PASS_NONE;
		psc->psc_key_file_pass.password_data = NULL;
	}

	if (psc->psc_unwrapped_secret != NULL) {
		memset(psc->psc_unwrapped_secret, 0, psc->psc_unwrapped_secret_len);
		free(psc->psc_unwrapped_secret);
		psc->psc_unwrapped_secret = NULL;
	}

	/* The crypto items */
	if (psc->psc_mpass != NULL)
	{
		mpass_destroy_handle(psc->psc_mpass);
		psc->psc_mpass = NULL;
	}

    /* Now the structure itself */
    free(psc);

}

/* ---------------------------------------------------------------- *
* Encryption routines
* ---------------------------------------------------------------- */

authme_err_t 
authme_load_master_password(authme_service_config_t * psc, char * password)
{

	mpass_handle out;
	authme_err_t ret;

	if (psc->psc_key_file == NULL)
		return AUTHME_ERR_INVALID_FILENAME;

	ret = mpass_load_master_password(psc->psc_key_file, password, &out);

	if (ret == AUTHME_ERR_OK)
		psc->psc_mpass = out;

	return ret;


}

authme_err_t 
authme_load_user_public_key(authme_service_config_t * psc, char * b64_key) 
{
	authme_err_t ret;

	if (psc->psc_mpass == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	ret = mpass_load_user_public_key(psc->psc_mpass, b64_key);

	if (ret != AUTHME_ERR_OK)
	{
		psc->psc_last_error = mpass_get_error_string(psc->psc_mpass);
	}

	return ret;
}

authme_err_t 
authme_generate_master_password(authme_service_config_t * psc, char * password)
{
	authme_err_t ret;
	mpass_handle out;

	ret = mpass_gen_and_save_master_password(psc->psc_key_file, password, &out);
	if (ret != AUTHME_ERR_OK)
	{
		psc->psc_last_error = strdup("Error in keygen process");
	}
	else
		psc->psc_mpass = out;

	return ret;

}

#if defined WIN32
authme_err_t authme_init_win32_lsa_key(authme_service_config_t * psc)
{
	authme_err_t ret;
	mpass_handle out = NULL;
	ret = mpass_init_w32_lsa_key(&out);

	if (ret != AUTHME_ERR_OK)
	{
		psc->psc_last_error = mpass_get_error_string(out);
	}
	else
		psc->psc_mpass = out;

	return ret;

}

authme_err_t 
authme_w32_load_master_password(authme_service_config_t * psc)
{
	authme_err_t ret;
	mpass_handle out = NULL;

	ret = mpass_w32_load_master_password(&out);
	if (ret != AUTHME_ERR_OK)
	{
		psc->psc_last_error = strdup(mpass_get_error_string(out));
	}
	else
		psc->psc_mpass = out;

	return ret;

}

#endif 

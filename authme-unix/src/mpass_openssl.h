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

#if defined HAVE_OPENSSL

#ifndef AUTHME_MPASS_OPENSSL_H
#define AUTHME_MPASS_OPENSSL_H

#ifndef WIN32
#	include "config.h"
#endif

#include "service.h"

#include <openssl/evp.h>

/*
* Master Password configuration
*
*/

typedef struct authme_master_password_s {

	EVP_PKEY    * amp_service_key;			/* Key everyone will use when talking to me */
	EVP_PKEY    * amp_service_public_key;	/* Public part of key people use to talk to me*/
	EVP_PKEY 	* amp_user_public_key;		/* Key used to validate or encrypt something to a user */

	char		* amp_last_error;			/* Error string for last error*/


} authme_master_password_t, *pauthme_master_password_t;

/* Initialisation */

mpass_function_table_t *
mpass_openssl_init();

void
mpass_openssl_shutdown();

authme_err_t
mpass_openssl_load_master_password(char * infile, char * password, mpass_handle * out);
authme_err_t
mpass_openssl_load_user_public_key(mpass_handle mh, char * b64_key);

char * mpass_openssl_get_error_string(mpass_handle mh);

authme_err_t
mpass_openssl_envelope_encrypt(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_openssl_envelope_decrypt(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_openssl_encrypt_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);
authme_err_t
mpass_openssl_decrypt_file_from_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);

authme_err_t
mpass_openssl_b64_encode(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf);
authme_err_t
mpass_openssl_b64_decode(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len);

// Random bytes
authme_err_t
mpass_openssl_random_bytes(mpass_handle mh, unsigned char * out, int bytes);

authme_err_t
mpass_openssl_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out);

void
mpass_openssl_destroy_handle(mpass_handle mh);

#if defined WIN32
authme_err_t
mpass_openssl_init_w32_lsa_key(mpass_handle * out);
authme_err_t
mpass_openssl_w32_load_master_password(mpass_handle * out);
#endif


#endif

#endif /* HAVE_OPENSSL */

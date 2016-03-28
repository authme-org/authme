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

#if defined HAVE_WINCAPI

#ifndef AUTHME_MPASS_WINDOWS_H
#define AUTHME_MPASS_WINDOWS_H

#ifndef WIN32
#	include "config.h"
#endif

#include "service.h"
#include "mpass.h"

#include <Windows.h>
#include <bcrypt.h>

/*
* Master Password configuration
*
*/

typedef struct authme_master_password_s {

	BCRYPT_ALG_HANDLE	 * amp_bcrypt_rsa;			/* Windows provider opened to handle our keys */
	BCRYPT_ALG_HANDLE	 * amp_bcrypt_rng;			/* Windows provider opened to handle random number generation */
	BCRYPT_ALG_HANDLE	 * amp_bcrypt_aes;			/* Windows provider opened to handle random number generation */
	BCRYPT_KEY_HANDLE    * amp_service_key;			/* Key everyone will use when talking to me */
	BCRYPT_KEY_HANDLE    * amp_user_public_key;		/* Key used to validate or encrypt something to a user */

	char		* amp_last_error;			/* Error string for last error*/


} authme_master_password_t, *pauthme_master_password_t;

#define MPASS_AES_MAX_KEY_LENGTH		32
#define MPASS_AES_BLOCK_SIZE			16
#define MPASS_AES_IV_LENGTH				16

/* Initialisation */

mpass_function_table_t *
mpass_windows_init();

void
mpass_windows_shutdown();

authme_err_t
mpass_windows_load_master_password(char * infile, char * password, mpass_handle * out);
authme_err_t
mpass_windows_load_user_public_key(mpass_handle mh, char * b64_key);

char * mpass_windows_get_error_string(mpass_handle mh);

authme_err_t
mpass_windows_envelope_encrypt(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_windows_envelope_decrypt(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_windows_encrypt_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);
authme_err_t
mpass_windows_decrypt_file_from_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);

authme_err_t
mpass_windows_b64_encode(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf);
authme_err_t
mpass_windows_b64_decode(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len);

// Random bytes
authme_err_t
mpass_windows_random_bytes(mpass_handle mh, unsigned char * out, int bytes);

void mpass_windows_destroy_handle(mpass_handle mh);

authme_err_t
mpass_windows_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out);

#if defined WIN32
authme_err_t
mpass_windows_init_w32_lsa_key(mpass_handle * out);
authme_err_t
mpass_windows_w32_load_master_password(mpass_handle * out);
#endif

#endif

#endif /* HAVE_OPENSSL */

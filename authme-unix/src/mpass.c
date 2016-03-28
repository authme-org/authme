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

#include "mpass.h"

#include <stdlib.h>

/*
 * Global function table - intialised at startup
 */

mpass_function_table_t * MPASS_FUNCTIONS = NULL;

/* For defaults */

#if defined HAVE_OPENSSL
/* Default for now */
mpass_function_table_t * mpass_openssl_init();
#endif

#if defined HAVE_WINCAPI
mpass_function_table_t * mpass_windows_init();
#endif

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */

/* Initialise the function table */

void
mpass_init(MPASS_INIT * provider) {

	/* TODO: Remove defaults*/
	if (provider != NULL)
		MPASS_FUNCTIONS = (provider)();

#if defined HAVE_OPENSSL
	/* Default for now */
	MPASS_FUNCTIONS = mpass_openssl_init();
#else
#if defined HAVE_WINCAPI
	MPASS_FUNCTIONS = mpass_windows_init();
#endif
#endif

}

void
mpass_shutdown() {

	if (MPASS_FUNCTIONS != NULL)
	{
		free(MPASS_FUNCTIONS);
		MPASS_FUNCTIONS = NULL;
	}
}

/* ---------------------------------------------------------------- *
* Function maps
* ---------------------------------------------------------------- */

authme_err_t
mpass_load_master_password(char * infile, char * password, mpass_handle * out) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->load_master_password == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->load_master_password)(infile, password, out);
}

authme_err_t
mpass_load_user_public_key(mpass_handle amp, char * b64_key) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->load_user_public_key == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->load_user_public_key)(amp, b64_key);
}

char * mpass_get_error_string(mpass_handle amp) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->get_error_string == NULL)
		return NULL;

	return (MPASS_FUNCTIONS->get_error_string)(amp);
}

authme_err_t
mpass_envelope_encrypt(mpass_handle amp, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->envelope_encrypt == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->envelope_encrypt)(amp, key,  in_buf, in_buf_len, out_buf, out_buf_len);
}

authme_err_t
mpass_envelope_decrypt(mpass_handle amp, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->envelope_decrypt == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->envelope_decrypt)(amp, key, in_buf, out_buf, out_buf_len);
}

authme_err_t
mpass_encrypt_file_to_file(mpass_handle amp, unsigned char * key, FILE * in, FILE * out) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->encrypt_file_to_file == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->encrypt_file_to_file)(amp, key, in, out);
}

authme_err_t
mpass_decrypt_file_from_file(mpass_handle amp, unsigned char * key, FILE * in, FILE * out) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->decrypt_file_from_file == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->decrypt_file_from_file)(amp, key, in, out);
}

authme_err_t
mpass_b64_encode(mpass_handle amp, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->b64_encode == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->b64_encode)(amp, in_buf, in_buf_len, out_buf);
}

authme_err_t
mpass_b64_decode(mpass_handle amp, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->b64_decode == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->b64_decode)(amp, in_b64, out_buf, out_buf_len);
}

// Random bytes
authme_err_t
mpass_random_bytes(mpass_handle amp, unsigned char * out, int bytes) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->random_bytes == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->random_bytes)(amp, out, bytes);
}

void mpass_destroy_handle(mpass_handle mh)
{
	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->destroy_handle == NULL)
		return;

	(MPASS_FUNCTIONS->destroy_handle)(mh);

}

authme_err_t
mpass_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out)
{
	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->gen_and_save_master_password == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->gen_and_save_master_password)(outfile, password, out);
}

#if defined WIN32
authme_err_t
mpass_init_w32_lsa_key(mpass_handle* out) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->init_w32_lsa_key == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->init_w32_lsa_key)(out);
}

authme_err_t
mpass_w32_load_master_password(mpass_handle* out) {

	if (MPASS_FUNCTIONS == NULL || MPASS_FUNCTIONS->w32_load_master_password == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	return (MPASS_FUNCTIONS->w32_load_master_password)(out);
}

#endif

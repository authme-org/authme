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
 * The "Master Password" in AuthMe is essentially the crypto interface
 * that both manages keys and algorithms.
 *
 * In the c code the mpass files abstract the crypto API so we can plug
 * modules underneath for OpenSSL and the Windows Crypto API (and 
 * theoretically anything else we want in the futugre)
 *
 * Silly name - comes from some of the original design for the iPhone 
 * code where everythign is based around a master password that
 * initialises the device.
 */

#ifndef AUTHME_MPASS_H
#define AUTHME_MPASS_H

#ifndef WIN32
#	include "config.h"
#endif

#include "service.h"

#include <stdio.h>

/* Opaque type that the plugins can use to pass info */
typedef void * mpass_handle;

/* Function definitions */

typedef authme_err_t
(MPASS_LOAD_MASTER_PASSWORD)(char * infile, char * password, mpass_handle * out);
typedef authme_err_t
(MPASS_LOAD_USER_PUBLIC_KEY)(mpass_handle mh, char * b64_key);
typedef char * 
(MPASS_GET_ERROR_STRING)(mpass_handle mh);
typedef authme_err_t
(MPASS_ENVELOPE_ENCRYPT)(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len);
typedef authme_err_t
(MPASS_ENVELOPE_DECRYPT)(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len);
typedef authme_err_t
(MPASS_ENCRYPT_FILE_TO_FILE)(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);
typedef authme_err_t
(MPASS_DECRYPT_FILE_FROM_FILE)(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);

typedef authme_err_t
(MPASS_B64_ENCODE)(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf);
typedef authme_err_t
(MPASS_B64_DECODE)(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len);
typedef authme_err_t
(MPASS_GEN_AND_SAVE_MASTER_PASSWORD)(char * outfile, char * password, mpass_handle * out);


// Random bytes
typedef authme_err_t
(MPASS_RANDOM_BYTES)(mpass_handle mh, unsigned char * out, int bytes);

// Shutdown
typedef void (MPASS_DESTROY_HANDLE)(mpass_handle mh);
typedef void (MPASS_SHUTDOWN)();

#if defined WIN32
typedef authme_err_t
(MPASS_INIT_W32_LSA_KEY)(mpass_handle * out);
typedef authme_err_t
(MPASS_W32_LOAD_MASTER_PASSWORD)(mpass_handle * out);
#endif

typedef struct MPASS_FUNCTION_TABLE_S {
	MPASS_LOAD_MASTER_PASSWORD			* load_master_password;
	MPASS_LOAD_USER_PUBLIC_KEY			* load_user_public_key;
	MPASS_GET_ERROR_STRING				* get_error_string;
	MPASS_ENVELOPE_ENCRYPT				* envelope_encrypt;
	MPASS_ENVELOPE_DECRYPT				* envelope_decrypt;
	MPASS_ENCRYPT_FILE_TO_FILE			* encrypt_file_to_file;
	MPASS_DECRYPT_FILE_FROM_FILE		* decrypt_file_from_file;
	MPASS_B64_ENCODE					* b64_encode;
	MPASS_B64_DECODE					* b64_decode;
	MPASS_RANDOM_BYTES					* random_bytes;
	MPASS_DESTROY_HANDLE				* destroy_handle;
	MPASS_GEN_AND_SAVE_MASTER_PASSWORD  * gen_and_save_master_password;
#if defined WIN32
	MPASS_INIT_W32_LSA_KEY				* init_w32_lsa_key;
	MPASS_W32_LOAD_MASTER_PASSWORD		* w32_load_master_password;
#endif

} mpass_function_table_t;

typedef mpass_function_table_t *
(MPASS_INIT)();

/*
* Master Password configuration
*
*/


/* Initialisation */

void
mpass_init(MPASS_INIT * provider);

void
mpass_shutdown();

authme_err_t
mpass_load_master_password(char * infile, char * password, mpass_handle * out);
authme_err_t 
mpass_load_user_public_key(mpass_handle mh, char * b64_key);

char * mpass_get_error_string(mpass_handle mh);

authme_err_t
mpass_envelope_encrypt(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_envelope_decrypt(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len);
authme_err_t
mpass_encrypt_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);
authme_err_t
mpass_decrypt_file_from_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out);

authme_err_t
mpass_b64_encode(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf);
authme_err_t
mpass_b64_decode(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len);

authme_err_t
mpass_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out);


void mpass_destroy_handle(mpass_handle mh);

// Random bytes
authme_err_t
mpass_random_bytes(mpass_handle mh, unsigned char * out, int bytes);

#if defined WIN32
authme_err_t
mpass_init_w32_lsa_key(mpass_handle* out);
authme_err_t
mpass_w32_load_master_password(mpass_handle* out);
#endif


#endif
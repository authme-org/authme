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

/* Only compile this if openssl is available */
#if defined HAVE_OPENSSL

#include "mpass_openssl.h"
#if defined WIN32
#include "AuthMeWindows.h"
#endif

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#pragma warning(disable : 4996)
#if defined WIN32
/* This is needed for Windows DLL linking */
#include <openssl/applink.c>
#endif

#if defined WIN32
#	ifndef WINVER
#		define WINVER 0x0600
#		include "targetver.h"
#	endif

#	define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

// Windows Header Files:
//#	ifndef WIN32_NO_STATUS
//#		include <ntstatus.h>
//#		define WIN32_NO_STATUS
//#	endif
#	include <windows.h>
#	include <ntsecapi.h>
#	include <wchar.h>
//#	define SECURITY_WIN32
//#include <security.h>
//#include <intsafe.h>

//#include <credentialprovider.h>

#endif

/* They key used to store the privatre key in windows in the LSA policy*/
#if defined WIN32
WCHAR * wszAuthMeLSAKeyName = L"L$AuthMePrivateKey";
#endif

/* ---------------------------------------------------------------- *
* Error string handling
* ---------------------------------------------------------------- */


char * mpass_openssl_get_error_string(mpass_handle mh) { return ((authme_master_password_t *)mh)->amp_last_error; }
#define MPASS_SET_ERROR(X,Y) {if (X->amp_last_error != NULL) {free (X->amp_last_error) ;} X->amp_last_error = strdup(Y); }


/*
* Master Password configuration
*
*/

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */


mpass_function_table_t *
mpass_openssl_init()
{
	mpass_function_table_t * ret;

	/* First initialise OpenSSL */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Now create the function mapping table */
	ret = (mpass_function_table_t *)malloc(sizeof (mpass_function_table_t));
	memset(ret, 0, sizeof(mpass_function_table_t));

	/* Map in the OpenSSL functions */
	ret->load_master_password = mpass_openssl_load_master_password;
	ret->load_user_public_key = mpass_openssl_load_user_public_key;
	ret->get_error_string = mpass_openssl_get_error_string;
	ret->envelope_encrypt = mpass_openssl_envelope_encrypt;
	ret->envelope_decrypt = mpass_openssl_envelope_decrypt;
	ret->encrypt_file_to_file = mpass_openssl_encrypt_file_to_file;
	ret->decrypt_file_from_file = mpass_openssl_decrypt_file_from_file;
	ret->b64_encode = mpass_openssl_b64_encode;
	ret->b64_decode = mpass_openssl_b64_decode;
	ret->random_bytes = mpass_openssl_random_bytes;
	ret->destroy_handle = mpass_openssl_destroy_handle;
    ret->gen_and_save_master_password = mpass_openssl_gen_and_save_master_password;
#if defined WIN32
	ret->init_w32_lsa_key = mpass_openssl_init_w32_lsa_key;
	ret->w32_load_master_password = mpass_openssl_w32_load_master_password;
#endif

	return ret;

}

void
mpass_openssl_shutdown()
{
	/* Clean up OpenSSL */

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

}

void
mpass_openssl_destroy_handle(mpass_handle mh)
{

    authme_master_password_t * amp;

    amp = mh;

    if (mh == NULL)
        return;

    if (amp->amp_service_key != NULL)
        EVP_PKEY_free(amp->amp_service_key);
    if (amp->amp_service_public_key != NULL)
        EVP_PKEY_free(amp->amp_service_public_key);
    if (amp->amp_user_public_key != NULL)
        EVP_PKEY_free(amp->amp_user_public_key);

    free(amp);

}

/* ---------------------------------------------------------------- *
* Initial load
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_load_master_password(char * infile, char * password, mpass_handle * out)
{

	FILE * input_file;
	EVP_PKEY * master_key;
	EVP_PKEY * pub_master_key;
	RSA * rsa_master_key;
	RSA * rsa_pub_master_key;
	authme_master_password_t * ret;

	// Can we open the file?
	if ((input_file = fopen(infile, "r")) == NULL)
	{
		*out = NULL;
		return AUTHME_ERR_INVALID_FILENAME;
	}

	// Can we load it?
	master_key = NULL;
	// if (!PEM_read_PrivateKey(input_file, &master_key, NULL, password))
    if (!d2i_PKCS8PrivateKey_fp(input_file, &master_key, NULL, password))
	{
        /* Try to read it as a PKCS8 object and then transform */
        PKCS8_PRIV_KEY_INFO * p8info;

        rewind(input_file);
        master_key = NULL;
        p8info = d2i_PKCS8_PRIV_KEY_INFO_fp(input_file, NULL);
        if (p8info)
        {
            master_key = EVP_PKCS82PKEY(p8info);
        }

        if (master_key == NULL)
        {
            fclose(input_file);
            *out = NULL;
            return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
        }
	}

	fclose(input_file);

	// Setup the public key for later use
	rsa_master_key = EVP_PKEY_get1_RSA(master_key);
	if (rsa_master_key == NULL)
	{
		EVP_PKEY_free(master_key);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	rsa_pub_master_key = RSAPublicKey_dup(rsa_master_key);
	pub_master_key = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(pub_master_key, rsa_pub_master_key) <= 0)
	{
		EVP_PKEY_free(master_key);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	// Loaded OK - let's create the structure
	ret = (authme_master_password_t *)malloc(sizeof(authme_master_password_t));
	ret->amp_service_key = master_key;
	ret->amp_last_error = NULL;
	ret->amp_service_public_key = pub_master_key;

	RSA_free(rsa_pub_master_key);
	RSA_free(rsa_master_key);

	*out = ret;

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Load a user public key
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_load_user_public_key(mpass_handle mh, char * b64_key)
{

	BIO *b64, *bmem;
	size_t b64_key_length;
	RSA * in_key;
	authme_master_password_t * amp = (authme_master_password_t *) mh;

	b64_key_length = strlen(b64_key);

	/* Load into BIO structure to do the read */
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(b64_key, (int)b64_key_length);
	bmem = BIO_push(b64, bmem);

	/* Now have the plain version - load into an RSA key */
	in_key = d2i_RSA_PUBKEY_bio(bmem, NULL);
	BIO_free_all(bmem);

	if (in_key == NULL)
	{
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_INVALID_KEY;
	}

	// Convert 
	amp->amp_user_public_key = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(amp->amp_user_public_key, in_key) <= 0)
	{
		RSA_free(in_key);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	RSA_free(in_key);
	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Encrypt with a randomly generated AES key and then wrap the key
* using the provided public key
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_envelope_encrypt(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len)
{
	unsigned char * worker_buf;
	int worker_buf_len;
	unsigned char * wrap_buf;
	size_t wrap_buf_len;
	int i, j;
	EVP_CIPHER_CTX *ctx;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY * pkey;
	unsigned char aes_key[EVP_MAX_KEY_LENGTH];
	unsigned char aes_iv[EVP_MAX_IV_LENGTH];
	int aes_iv_len;
	int aes_key_len;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	if (amp == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	/* Sanity check */
	switch (key)
	{
	case MPASS_SERVICE_PUBLIC_KEY:
		pkey = amp->amp_service_public_key;
		break;
	case MPASS_USER_PUBLIC_KEY:
		pkey = amp->amp_user_public_key;
		break;
	default:
		MPASS_SET_ERROR(amp, "Unknown key passed into envelope encrypt");
		return AUTHME_ERR_INVALID_KEY;
	}

	/* Allocate enough space for the AES crypto part*/
	worker_buf_len = (int)in_buf_len + EVP_MAX_BLOCK_LENGTH + EVP_MAX_IV_LENGTH;
	if ((worker_buf = (unsigned char *)malloc(worker_buf_len)) == NULL)
	{
		// This would be bad!
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	// Now start creating keys and things
	if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 ||
		RAND_bytes(aes_iv, sizeof(aes_iv)) != 1 ||
		(ctx = EVP_CIPHER_CTX_new()) == NULL)
	{
		// Also bad
		free(worker_buf);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_INIT;
	}

	EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv, 1);
	aes_iv_len = EVP_CIPHER_CTX_iv_length(ctx);
	aes_key_len = EVP_CIPHER_CTX_key_length(ctx);

	/* Sanity checks */
	if ((aes_iv_len + in_buf_len + EVP_CIPHER_CTX_block_size(ctx)) > worker_buf_len)
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, "Internal assertion on buffer lengths failed - help!");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Easy day - let's encrypt!
	memcpy(worker_buf, aes_iv, aes_iv_len);
	i = worker_buf_len - aes_iv_len;
	if (!EVP_CipherUpdate(ctx, &worker_buf[aes_iv_len], &i, in_buf, (int)in_buf_len))
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;

	}
	j = worker_buf_len - aes_iv_len - i;

	if (!EVP_CipherFinal_ex(ctx, &worker_buf[aes_iv_len + i], &j))
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Done the AES part
	EVP_CIPHER_CTX_free(ctx);
	worker_buf_len = aes_iv_len + i + j;

	// Now the RSA part
	if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Initialise ctx
	if (EVP_PKEY_encrypt_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Get buffer length to write to
	if (EVP_PKEY_encrypt(pctx, NULL, &wrap_buf_len, aes_key, aes_key_len) <= 0)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if ((wrap_buf = (unsigned char *)malloc(wrap_buf_len)) == NULL)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, "Error allocating memory for crypto operation");
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	// Encrypt
	if (EVP_PKEY_encrypt(pctx, wrap_buf, &wrap_buf_len, aes_key, aes_key_len) <= 0)
	{
		free(worker_buf);
		free(wrap_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Done - cleanup and copy to output
	memset(aes_key, 0, sizeof(aes_key));

	*out_buf_len = 4 + (int)wrap_buf_len + worker_buf_len;
	if ((*out_buf = (unsigned char *)malloc(*out_buf_len)) == NULL)
	{
		free(worker_buf);
		free(wrap_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, "Error allocating final buffer");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// For our envelope, start of the buffer is always a 4 byte unsigned int
	(*out_buf)[0] = ((unsigned int)wrap_buf_len >> 24) & 0xFF;
	(*out_buf)[1] = ((unsigned int)wrap_buf_len >> 16) & 0xFF;
	(*out_buf)[2] = ((unsigned int)wrap_buf_len >> 8) & 0xFF;
	(*out_buf)[3] = (unsigned int)wrap_buf_len & 0xFF;

	// Then the wrap itself
	memcpy(&((*out_buf)[4]), wrap_buf, wrap_buf_len);

	// then the encrypted data
	memcpy(&((*out_buf)[4 + wrap_buf_len]), worker_buf, worker_buf_len);

	free(worker_buf);
	free(wrap_buf);

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Generate random data
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_random_bytes(mpass_handle mh, unsigned char * out, int bytes)
{
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	if (RAND_bytes(out, bytes) != 1)
	{
		MPASS_SET_ERROR(amp, "Error generating random bytes");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	return AUTHME_ERR_OK;
}
/* ---------------------------------------------------------------- *
* Read from in, encrypt and write to out  AES 256 is used
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_cipher_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out, int encrypt)
{
	EVP_CIPHER_CTX *ctx;
	unsigned char aes_iv[EVP_MAX_IV_LENGTH];
	unsigned char in_buf[1024];
	unsigned char out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
	int bytes_read, i;
	int aes_iv_len;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	// Now start creating keys and things
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
	{
		// Also bad
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Set up the IV */
	aes_iv_len = 16;
	if (encrypt)
	{
		if (RAND_bytes(aes_iv, sizeof(aes_iv)) != 1)
		{
			// A bad start!
			MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
			return AUTHME_ERR_CRYPTO_INIT;
		}
		else
		{
			fwrite(aes_iv, 1, aes_iv_len, out);
		}
	}
	else
	{
		if (fread(aes_iv, 1, aes_iv_len, in) != aes_iv_len)
		{
			MPASS_SET_ERROR(amp, "Not enough bytes to load IV from input file");
			return AUTHME_ERR_CRYPTO_INIT;
		}
	}

	/* Set up the cipher */
	EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, aes_iv, encrypt);

	/* Now we loop */
	while (!feof(in))
	{
		bytes_read = (int)fread(in_buf, 1, 1024, in);
		i = 1024 + EVP_MAX_BLOCK_LENGTH;

		if (!EVP_CipherUpdate(ctx, out_buf, &i, in_buf, bytes_read))
		{
			EVP_CIPHER_CTX_free(ctx);
			MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
			return AUTHME_ERR_CRYPTO_OPERATION;
		}

		fwrite(out_buf, 1, i, out);
	}

	i = 1024 + EVP_MAX_BLOCK_LENGTH;
	if (!EVP_CipherFinal_ex(ctx, out_buf, &i))
	{
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, (ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	fwrite(out_buf, 1, i, out);

	// Done the AES part
	EVP_CIPHER_CTX_free(ctx);

	return AUTHME_ERR_OK;
}

authme_err_t
mpass_openssl_encrypt_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out)
{
	/* Simply do a cipher operation with encrypt set to 1 */
	return mpass_openssl_cipher_file_to_file(mh, key, in, out, 1);
}

authme_err_t
mpass_openssl_decrypt_file_from_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out)
{
	/* Simply do a cipher operation with encrypt set to 0 (derypt) */
	return mpass_openssl_cipher_file_to_file(mh, key, in, out, 0);
}

/* ---------------------------------------------------------------- *
* Decrypt an envelope using our key if we have one
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_envelope_decrypt(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len)
{
	unsigned char * worker_buf;
	size_t worker_buf_len;
	unsigned char * wrap_buf;
	size_t enc_wrap_buf_len, wrap_buf_len;
	unsigned char * secret_buf;
	int aes_iv_len, enc_secret_len;
	int i, j;
	EVP_PKEY * pkey;
	EVP_CIPHER_CTX *ctx;
	EVP_PKEY_CTX *pctx;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	authme_err_t err;

	if (amp == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	/* For now we only know how to decrypt using the service private key */
	if (key != MPASS_SERVICE_PRIVATE_KEY)
	{
		MPASS_SET_ERROR(amp, "Can only unwrap using service private key");
		return AUTHME_ERR_INVALID_KEY;
	}

	pkey = amp->amp_service_key;
	if (pkey == NULL)
	{
		MPASS_SET_ERROR(amp, "Private key not loaded");
		return AUTHME_ERR_INVALID_KEY;
	}

	/* Decode the buffer */
	if ((err = mpass_openssl_b64_decode(amp, in_buf, &worker_buf, &worker_buf_len)) != AUTHME_ERR_OK)
		return err;

	if (worker_buf_len < 4)
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Base64 decode buffer too short");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Get size of wrap */
	wrap_buf_len = 0;
	enc_wrap_buf_len = 0;
	for (i = 0; i < 4; ++i)
	{
		enc_wrap_buf_len = enc_wrap_buf_len << 8;
		enc_wrap_buf_len = enc_wrap_buf_len | worker_buf[i];
	}

	if (enc_wrap_buf_len > worker_buf_len + 4 || enc_wrap_buf_len <= 0)
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Wrapped key buffer size invalid");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Decrypt the wrap */
	if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Initialise ctx
	if (EVP_PKEY_decrypt_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Get buffer length to write to
	if (EVP_PKEY_decrypt(pctx, NULL, &wrap_buf_len, &(worker_buf[4]), enc_wrap_buf_len) <= 0)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if ((wrap_buf = (unsigned char *)malloc(wrap_buf_len)) == NULL)
	{
		free(worker_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, "Error allocating memory for crypto operation");
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	// Decrypt
	if (EVP_PKEY_decrypt(pctx, wrap_buf, &wrap_buf_len, &(worker_buf[4]), enc_wrap_buf_len) <= 0)
	{
		free(worker_buf);
		free(wrap_buf);
		EVP_PKEY_CTX_free(pctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Free the key */
	EVP_PKEY_CTX_free(pctx);

	/* Have an AES key - let's use it */
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
	{
		// Bad
		free(worker_buf);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_INIT;
	}

	EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, wrap_buf, &(worker_buf[4 + enc_wrap_buf_len]), 0);
	aes_iv_len = EVP_CIPHER_CTX_iv_length(ctx);
	memset(wrap_buf, 0, wrap_buf_len);
	free(wrap_buf);

	/* Sanity checks */
	enc_secret_len = (int)worker_buf_len - 4 - (int)enc_wrap_buf_len - aes_iv_len;
	if (enc_secret_len <= 0)
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, "Internal assertion on buffer lengths failed - help!");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Holding buffer */
	if ((secret_buf = (unsigned char*)malloc(enc_secret_len)) == NULL)
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, "Memory allocation error");
		return AUTHME_ERR_OUT_OF_MEMORY;

	}

	// Decrypt
	i = enc_secret_len;
	if (!EVP_CipherUpdate(ctx, secret_buf, &i, &worker_buf[4 + enc_wrap_buf_len + aes_iv_len], enc_secret_len))
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}
	j = enc_secret_len - i;

	if (!EVP_CipherFinal_ex(ctx, &secret_buf[i], &j))
	{
		free(worker_buf);
		EVP_CIPHER_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Done the AES part
	EVP_CIPHER_CTX_free(ctx);

	// Return
	*out_buf_len = i + j;
	*out_buf = secret_buf;

	return AUTHME_ERR_OK;
}


/* ---------------------------------------------------------------- *
* Base64 encode a buffer
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_b64_encode(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf)
{

	BIO * bmem, *b64;
	BUF_MEM * bptr;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_push(b64, bmem);

	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bmem, in_buf, (int)in_buf_len);
	BIO_flush(bmem);
	BIO_get_mem_ptr(bmem, &bptr);

	*out_buf = strdup(bptr->data);

	// Now free and leave
	BIO_free_all(bmem);

	return AUTHME_ERR_OK;
}

/* ---------------------------------------------------------------- *
* Base64 decode a buffer
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_b64_decode(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len)
{
	BIO * bmem, *b64;
	int in_len;
	authme_err_t ret;
	int openssl_ret;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	in_len = (int)strlen(in_b64);
	*out_buf = (unsigned char *)malloc(in_len);

	bmem = BIO_new_mem_buf(in_b64, in_len);
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_push(b64, bmem);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	openssl_ret = BIO_read(bmem, *out_buf, in_len);

	if (openssl_ret <= 0)
	{
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		ret = AUTHME_ERR_BASE64_FAILED;
		*out_buf_len = 0;
	}
	else {
		ret = AUTHME_ERR_OK;
		*out_buf_len = (size_t)openssl_ret;
	}

	BIO_free_all(bmem);

	return ret;

}

/* ---------------------------------------------------------------- *
* Generate a new RSA key and store in a PKCS8 format file
* ---------------------------------------------------------------- */

authme_err_t
mpass_openssl_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out)
{

	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkey_pub = NULL;
    RSA * rsa = NULL;
    RSA * rsa_pub = NULL;
    FILE * outfp;
    authme_master_password_t * amp;

    /* First we generate the new key */
	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
		EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

    /* Save in the output file */
    if ((outfp = fopen(outfile, "wb")) == NULL)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return AUTHME_ERR_INVALID_FILENAME;
    }

    int res;

    /* Do we have a password? */
    if (password == NULL || password[0] == '\0')
    {
        /* Have no password */
        res = i2d_PKCS8PrivateKey_fp(
            outfp,
            pkey,
            NULL,
            NULL, 0,   /* kstr arg */
            NULL,
            NULL);
    }
    else
    {
        int nid = OBJ_txt2nid("PBE-SHA1-3DES");
        res = i2d_PKCS8PrivateKey_nid_fp(
            outfp,
            pkey,
            nid,
            NULL,
            0,
            NULL,
            password);
    }

    fclose(outfp);

    if (!res)
    {
        /* Something went wrong */
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return AUTHME_ERR_CRYPTO_OPERATION;
    }

    /* All Good! */
	amp = (authme_master_password_t *)malloc(sizeof(authme_master_password_t));
	amp->amp_service_key = pkey;
	amp->amp_last_error = NULL;
	amp->amp_service_public_key = NULL;

    /* Create the pub key just in case */
    pkey_pub = EVP_PKEY_new();

    rsa = EVP_PKEY_get1_RSA(pkey);
    rsa_pub = RSAPublicKey_dup(rsa);
    RSA_free(rsa);

    EVP_PKEY_set1_RSA(pkey_pub, rsa_pub);

    amp->amp_service_public_key = pkey_pub;

    *out = amp;
    return AUTHME_ERR_OK;
}


/* ---------------------------------------------------------------- *
* Initialise the LSA key and save in the LSA private data area
* ---------------------------------------------------------------- */

#if defined WIN32
authme_err_t
mpass_openssl_init_w32_lsa_key(authme_master_password_t ** out)
{

	/* First we open the Policy store */
	LSA_OBJECT_ATTRIBUTES LSAObjectAttributes;
	LSA_HANDLE LSAHandle;
	NTSTATUS Status;
	LSA_UNICODE_STRING lucKeyName;
	LSA_UNICODE_STRING lucSecret;
	authme_master_password_t * amp;

	/* Initialise the crypto structure */
	// Loaded OK - let's create the structure
	*out = (authme_master_password_t *)malloc(sizeof(authme_master_password_t));
	(*out)->amp_service_key = NULL;
	(*out)->amp_last_error = NULL;
	(*out)->amp_service_public_key = NULL;

	amp = *out;

	ZeroMemory(&LSAObjectAttributes, sizeof(LSAObjectAttributes));
	LSAHandle = NULL;

	if ((Status = LsaOpenPolicy(NULL, &LSAObjectAttributes, POLICY_ALL_ACCESS, &LSAHandle)) != S_OK)
	{
		MPASS_SET_ERROR(amp, "Unable to open policy store");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if (LsaInitUnicodeString(&lucKeyName, wszAuthMeLSAKeyName) != S_OK)
	{
		LsaClose(LSAHandle);
		MPASS_SET_ERROR(amp, "Error creating LSA string");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Now we generate the new key */
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	BIO * bmem;

	bmem = BIO_new(BIO_s_mem());

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
	{
		LsaClose(LSAHandle);
		BIO_free(bmem);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
		EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		LsaClose(LSAHandle);
		BIO_free(bmem);
		EVP_PKEY_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	amp->amp_service_key = pkey;

	/* Turn it into a PEM object */
	if (!PEM_write_bio_PrivateKey(bmem, pkey, NULL, NULL, 0, NULL, NULL))
	{
		LsaClose(LSAHandle);
		BIO_free(bmem);
		EVP_PKEY_CTX_free(ctx);
		MPASS_SET_ERROR(amp, strdup(ERR_error_string(ERR_get_error(), NULL)));
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Grab the output buffer and transform into a unicode string */
	BUF_MEM * bptr;
	BIO_get_mem_ptr(bmem, &bptr);
	WCHAR * pwcBuffer;

	pwcBuffer = (WCHAR *)malloc(sizeof(WCHAR) * (bptr->length + 1));
	swprintf(pwcBuffer, bptr->length + 1, L"%.*hs", (int)bptr->length, bptr->data); /* flawfinder: ignore */

	if (LsaInitUnicodeString(&lucSecret, pwcBuffer) != S_OK)
	{
		LsaClose(LSAHandle);
		BIO_free(bmem);
		EVP_PKEY_CTX_free(ctx);
		free(pwcBuffer);
		MPASS_SET_ERROR(amp, "Error creating LSA string");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	Status = LsaStorePrivateData(LSAHandle, &lucKeyName, &lucSecret);

	/* Cleanup regardless */
	LsaClose(LSAHandle);
	BIO_free(bmem);
	EVP_PKEY_CTX_free(ctx);
	memset(pwcBuffer, 0, sizeof(pwcBuffer));
	free(pwcBuffer);

	if (Status == ERROR_ACCESS_DENIED) {
		MPASS_SET_ERROR(amp, "Error storing data - privs");
		return AUTHME_ERR_INSUFFICIENT_PRIVS;
	}

	if (Status != S_OK)
	{
		MPASS_SET_ERROR(amp, "Error storing data");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	return AUTHME_ERR_OK;

}

authme_err_t
mpass_openssl_w32_load_master_password(mpass_handle * out)
{

	/* First we open the Policy store */
	LSA_OBJECT_ATTRIBUTES LSAObjectAttributes;
	LSA_HANDLE LSAHandle;
	NTSTATUS Status;
	LSA_UNICODE_STRING lucKeyName;
	LSA_UNICODE_STRING * lucSecret;
	authme_master_password_t * amp;

	/* Initialise the crypto structure */
	// Loaded OK - let's create the structure
	amp = (authme_master_password_t *)malloc(sizeof(authme_master_password_t));
	amp->amp_service_key = NULL;
	amp->amp_last_error = NULL;
	amp->amp_service_public_key = NULL;

	*out = amp;


	/* First see if we can load */

	ZeroMemory(&LSAObjectAttributes, sizeof(LSAObjectAttributes));
	LSAHandle = NULL;

	if ((Status = LsaOpenPolicy(NULL, &LSAObjectAttributes, POLICY_ALL_ACCESS, &LSAHandle)) != S_OK)
	{
		MPASS_SET_ERROR(amp, "Unable to open policy store");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	if (LsaInitUnicodeString(&lucKeyName, wszAuthMeLSAKeyName) != S_OK)
	{
		LsaClose(LSAHandle);
		MPASS_SET_ERROR(amp, "Error creating LSA string");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Get the key... */
	Status = LsaRetrievePrivateData(LSAHandle, &lucKeyName, &lucSecret);
	LsaClose(LSAHandle);

	if (Status != S_OK || lucSecret == NULL || lucSecret->Buffer == NULL || lucSecret->Length == 0)
	{
		MPASS_SET_ERROR(amp, "Error creating LSA String");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	char * privateKeyBuffer = (char *)malloc(lucSecret->Length + 1);
	snprintf(privateKeyBuffer, lucSecret->Length + 1, "%.*S", lucSecret->Length, lucSecret->Buffer);

	// Would prefer to do this - but it causes errors.
	// wmemset((lucSecret->Buffer), 0, (lucSecret->Length) - 1);
	LsaFreeMemory(lucSecret);

	/* Load the key into the OpenSSL Structures */

	EVP_PKEY * master_key;
	EVP_PKEY * pub_master_key;
	RSA * rsa_master_key;
	RSA * rsa_pub_master_key;
	BIO *bmem = BIO_new_mem_buf(privateKeyBuffer, -1);

	// Can we load it?
	master_key = NULL;
	if (!PEM_read_bio_PrivateKey(bmem, &master_key, NULL, NULL))
	{
		memset(privateKeyBuffer, 0, strlen(privateKeyBuffer));
		free(privateKeyBuffer);
		MPASS_SET_ERROR(amp, "Loaded private key but couldn't decode");
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	memset(privateKeyBuffer, 0, strlen(privateKeyBuffer));
	free(privateKeyBuffer);

	BIO_free(bmem);

	// Setup the public key for later use
	rsa_master_key = EVP_PKEY_get1_RSA(master_key);
	if (rsa_master_key == NULL)
	{
		EVP_PKEY_free(master_key);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	rsa_pub_master_key = RSAPublicKey_dup(rsa_master_key);
	pub_master_key = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(pub_master_key, rsa_pub_master_key) <= 0)
	{
		EVP_PKEY_free(master_key);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	// Loaded OK - let's create the structure
	amp->amp_service_key = master_key;
	amp->amp_last_error = NULL;
	amp->amp_service_public_key = pub_master_key;

	RSA_free(rsa_pub_master_key);
	RSA_free(rsa_master_key);

	return AUTHME_ERR_OK;

}



#endif

#endif /* HAVE_OPENSSL */

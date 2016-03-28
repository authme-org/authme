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

/* Only compile this if we have the Windows Crypto API */
#if defined HAVE_WINCAPI


#include "mpass.h"
#include "mpass_windows.h"

#if defined WIN32
#include "AuthMeWindows.h"
#endif

#pragma comment(lib, "ncrypt")
#pragma comment(lib, "Crypt32")

#pragma warning(disable : 4996)

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
#	include <wincrypt.h>
//#	define SECURITY_WIN32
//#include <security.h>
//#include <intsafe.h>

//#include <credentialprovider.h>

#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#endif

/* They key used to store the privatre key in windows in the LSA policy*/
#if defined WIN32
WCHAR * wszAuthMeLSAKeyName = L"L$AuthMePrivateKey";
#endif

/* ---------------------------------------------------------------- *
* Error string handling
* ---------------------------------------------------------------- */


char * mpass_windows_get_error_string(mpass_handle mh) { return ((authme_master_password_t *)mh)->amp_last_error; }
#define MPASS_SET_ERROR(X,Y) {if (X->amp_last_error != NULL) {free (X->amp_last_error) ;} X->amp_last_error = strdup(Y); }


/*
* Master Password configuration
*
*/

/* ---------------------------------------------------------------- *
* Init and shutdown
* ---------------------------------------------------------------- */


mpass_function_table_t *
mpass_windows_init()
{
	mpass_function_table_t * ret;

	/* Now create the function mapping table */
	ret = (mpass_function_table_t *)malloc(sizeof(mpass_function_table_t));
	memset(ret, 0, sizeof(mpass_function_table_t));

	/* Map in the OpenSSL functions */
	ret->load_master_password = mpass_windows_load_master_password;
	ret->load_user_public_key = mpass_windows_load_user_public_key;
	ret->get_error_string = mpass_windows_get_error_string;
	ret->envelope_encrypt = mpass_windows_envelope_encrypt;
	ret->envelope_decrypt = mpass_windows_envelope_decrypt;
	ret->encrypt_file_to_file = mpass_windows_encrypt_file_to_file;
	ret->decrypt_file_from_file = mpass_windows_decrypt_file_from_file;
	ret->b64_encode = mpass_windows_b64_encode;
	ret->b64_decode = mpass_windows_b64_decode;
	ret->random_bytes = mpass_windows_random_bytes;
	ret->destroy_handle = mpass_windows_destroy_handle;
	ret->gen_and_save_master_password = mpass_windows_gen_and_save_master_password;
#if defined WIN32
	ret->init_w32_lsa_key = mpass_windows_init_w32_lsa_key;
	ret->w32_load_master_password = mpass_windows_w32_load_master_password;
#endif

	return ret;

}

void
mpass_windows_shutdown()
{

}

authme_master_password_t *
create_windows_amp() {

	authme_master_password_t * amp;
	BCRYPT_ALG_HANDLE bah;

	amp = (authme_master_password_t *)malloc(sizeof(authme_master_password_t));
	memset(amp, 0, sizeof(authme_master_password_t));

	/* RSA Provider */
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&bah, BCRYPT_RSA_ALGORITHM, NULL, 0)))
	{
		free(amp);
		return NULL;
	}

	amp->amp_bcrypt_rsa = bah;
	bah = 0;

	/* RNG Provider */
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&bah, BCRYPT_RNG_ALGORITHM, NULL, 0)))
	{
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rsa, 0);
		free(amp);
		return NULL;
	}
	amp->amp_bcrypt_rng = bah;

	/* AES Provider */
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&bah, BCRYPT_AES_ALGORITHM, NULL, 0)))
	{
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rsa, 0);
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rng, 0);
		free(amp);
		return NULL;
	}

	if (!NT_SUCCESS(BCryptSetProperty(bah, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
	{
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rsa, 0);
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rng, 0);
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_aes, 0);
		free(amp);
		return NULL;
	}

	amp->amp_bcrypt_aes = bah;

	return amp;

}

/* ---------------------------------------------------------------- *
* Destroy a handle
* ---------------------------------------------------------------- */

void mpass_windows_destroy_handle(mpass_handle mh)
{
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	if (amp == NULL)
		return;

	if (amp->amp_service_key != NULL)
		BCryptDestroyKey(amp->amp_service_key);
	if (amp->amp_user_public_key != NULL)
		BCryptDestroyKey(amp->amp_user_public_key);

	if (amp->amp_bcrypt_aes != NULL)
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_aes, 0);
	if (amp->amp_bcrypt_rng)
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rng, 0);
	if (amp->amp_bcrypt_rsa)
		BCryptCloseAlgorithmProvider(amp->amp_bcrypt_rsa, 0);

	if (amp->amp_last_error != NULL)
		free(amp->amp_last_error);

	memset(amp, 0, sizeof(authme_master_password_t));
	free(amp);
}

/* ---------------------------------------------------------------- *
* Initial load
* ---------------------------------------------------------------- */

/*
 * Load a PKCS8 format RSA key.
 *
 * NOTE: Must be saved using OpenSSL pkcs8 to8 -v1 PBE-SHA1-3DES
 */

authme_err_t
mpass_windows_load_master_password(char * infile, char * password, mpass_handle * out)
{


	FILE * input_file;
	NCRYPT_KEY_HANDLE ncrypt_master_key;
	BCRYPT_KEY_HANDLE bcrypt_master_key;

	NCRYPT_PROV_HANDLE prov_handle;
	NCryptBuffer buffers[2];
	NCryptBufferDesc params, *pparams;
	SECURITY_STATUS sec_stat;
	unsigned char * bcrypt_blob;
	DWORD bcrypt_blob_sz;
	authme_master_password_t * amp;

	/* Maximum read size */
	unsigned char raw_key_bytes[16384];

	/* Open the NCryptSTorageProvider */
	if (NCryptOpenStorageProvider(&prov_handle, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Can we open the file?
	if ((input_file = fopen(infile, "rb")) == NULL)
	{
		*out = NULL;
		return AUTHME_ERR_INVALID_FILENAME;
	}

	/* Read it into memory */
	size_t bytes_read = fread(raw_key_bytes, 1, 16384, input_file);
	fclose(input_file);

	if (bytes_read < 1) {
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	/* Import it */
	buffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;

	if (password != NULL && strlen(password) > 0)
	{
		buffers[0].pvBuffer = strToWStrDup(password);
		buffers[0].cbBuffer = (ULONG)(strlen(password) + 1) * 2;
		pparams = &params;
	}
	else
	{
		buffers[0].pvBuffer = NULL;
		buffers[0].cbBuffer = 0;
		pparams = NULL;
	}


	params.cBuffers = 1;
	params.pBuffers = buffers;
	params.ulVersion = NCRYPTBUFFER_VERSION;

	if ((sec_stat = NCryptImportKey(prov_handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &params, &ncrypt_master_key, raw_key_bytes, (DWORD) bytes_read, 0)) != ERROR_SUCCESS)
	{
		HRESULT raw2 = MAKE_HRESULT(1, FACILITY_WIN32, sec_stat);
		if (sec_stat == 0xC000003E)
		*out = NULL;
		if (buffers[0].pvBuffer != NULL)
			free(buffers[0].pvBuffer);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	if (buffers[0].pvBuffer != NULL)
		free(buffers[0].pvBuffer);

	DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	if ((sec_stat = NCryptSetProperty(ncrypt_master_key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&export_policy, sizeof(DWORD), 0)))
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Now have to export it into a BCrypt key */
	if ((sec_stat = NCryptExportKey(ncrypt_master_key, 0, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &bcrypt_blob_sz, 0)) != ERROR_SUCCESS)
	{
		//NTE_BAD_ALGID
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	bcrypt_blob = (unsigned char *)malloc(bcrypt_blob_sz);
	if (NCryptExportKey(ncrypt_master_key, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, bcrypt_blob, bcrypt_blob_sz, &bcrypt_blob_sz, 0) != ERROR_SUCCESS)
	{
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Read to import - set up the master password structure */
	if ((amp = create_windows_amp()) == NULL)
	{
		memset(bcrypt_blob, 0, bcrypt_blob_sz);
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_INIT;
	}

	if (!NT_SUCCESS(BCryptImportKeyPair(amp->amp_bcrypt_rsa, NULL, BCRYPT_RSAPRIVATE_BLOB, &bcrypt_master_key, bcrypt_blob, bcrypt_blob_sz, 0)))
	{
		memset(bcrypt_blob, 0, bcrypt_blob_sz);
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	memset(bcrypt_blob, 0, bcrypt_blob_sz);
	free(bcrypt_blob);

	/* WooHoo - well that was easy!  Get out of here */
	amp->amp_service_key = bcrypt_master_key;
	*out = amp;

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Create a master key file
* ---------------------------------------------------------------- */

/*
* Generate RSA key and save as a PKCS8 format  key.
*
*/

authme_err_t
mpass_windows_gen_and_save_master_password(char * outfile, char * password, mpass_handle * out)
{
	authme_master_password_t * amp;
	BCRYPT_KEY_HANDLE bcrypt_master_key;
	NCRYPT_KEY_HANDLE ncrypt_master_key;
	DWORD bcrypt_blob_sz;
	unsigned char * bcrypt_blob;
	NCRYPT_PROV_HANDLE prov_handle;
	NCryptBufferDesc params, *pparams;
	NCryptBuffer buffers[3];
	DWORD pkcs8_blob_sz;
	unsigned char * pkcs8_blob;
	FILE * output_file;
	CRYPT_PKCS12_PBE_PARAMS * pbe_params;
	unsigned char * salt;



	if ((amp = create_windows_amp()) == NULL)
	{
		return AUTHME_ERR_CRYPTO_INIT;
	}


	/* First we generate a new key */
	if (!NT_SUCCESS(BCryptGenerateKeyPair(amp->amp_bcrypt_rsa, &bcrypt_master_key, 2048, 0)))
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Finalise - required before any use */
	if (!NT_SUCCESS(BCryptFinalizeKeyPair(bcrypt_master_key, 0)))
	{
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Now we export it into a NCrypt format */
	if (!NT_SUCCESS(BCryptExportKey(bcrypt_master_key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &bcrypt_blob_sz, 0)))
	{
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Allocate a blob for storage and do the retreive */
	bcrypt_blob = (unsigned char *)malloc(bcrypt_blob_sz);
	if (!NT_SUCCESS(BCryptExportKey(bcrypt_master_key, NULL, BCRYPT_RSAPRIVATE_BLOB, bcrypt_blob, bcrypt_blob_sz, &bcrypt_blob_sz, 0)))
	{
		BCryptDestroyKey(bcrypt_master_key);
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Open the NCryptSTorageProvider */
	if (NCryptOpenStorageProvider(&prov_handle, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		BCryptDestroyKey(bcrypt_master_key);
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Now we tranform into a NCrypt key */
	if (NCryptImportKey(prov_handle, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &ncrypt_master_key, bcrypt_blob, bcrypt_blob_sz, 0) != ERROR_SUCCESS)
	{
		NCryptFreeObject(prov_handle);
		BCryptDestroyKey(bcrypt_master_key);
		free(bcrypt_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	memset(bcrypt_blob, 0, bcrypt_blob_sz);
	free(bcrypt_blob);

	/* And export it back into a PKCS8*/
	DWORD export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	if (NCryptSetProperty(ncrypt_master_key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&export_policy, sizeof(DWORD), 0) != ERROR_SUCCESS)
	{
		NCryptDeleteKey(ncrypt_master_key, 0);
		NCryptFreeObject(prov_handle);
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Generate the parameters
	pbe_params = (CRYPT_PKCS12_PBE_PARAMS *)malloc(sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8);
	memset(pbe_params, 0, sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8);
	salt = (unsigned char *) pbe_params + sizeof(CRYPT_PKCS12_PBE_PARAMS);

	// First some random
	if (!NT_SUCCESS(BCryptGenRandom(amp->amp_bcrypt_rng, salt, 8, 0)))
	{
		NCryptDeleteKey(ncrypt_master_key, 0);
		NCryptFreeObject(prov_handle);
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// Now the params
	pbe_params->cbSalt = 8;
	pbe_params->iIterations = 2048;

	buffers[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;
	buffers[2].cbBuffer = sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8;
	buffers[2].pvBuffer = pbe_params;

	buffers[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
	buffers[1].pvBuffer = szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES;
	buffers[1].cbBuffer = strlen(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES) + 1;


	buffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
	if (password != NULL && strlen(password) > 0)
	{
		buffers[0].pvBuffer = strToWStrDup(password);
		buffers[0].cbBuffer = (ULONG) (strlen(password) + 1) * 2;
	}
	else
	{
		buffers[0].pvBuffer = NULL;
		buffers[0].cbBuffer = 0;
	}

	params.cBuffers = 3;
	params.pBuffers = buffers;
	params.ulVersion = NCRYPTBUFFER_VERSION;

	pparams = buffers[0].pvBuffer != NULL ? &params : NULL;

	/* Do the export */
	if (NCryptExportKey(ncrypt_master_key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
		pparams, NULL, 0, &pkcs8_blob_sz, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		NCryptDeleteKey(ncrypt_master_key, 0);
		NCryptFreeObject(prov_handle);
		BCryptDestroyKey(bcrypt_master_key);
		if (buffers[0].pvBuffer != NULL)
			free(buffers[0].pvBuffer);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	pkcs8_blob = (unsigned char *)malloc(pkcs8_blob_sz);
	if (NCryptExportKey(ncrypt_master_key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
		pparams, pkcs8_blob, pkcs8_blob_sz, &pkcs8_blob_sz, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		free(pkcs8_blob);
		NCryptDeleteKey(ncrypt_master_key, 0);
		NCryptFreeObject(prov_handle);
		BCryptDestroyKey(bcrypt_master_key);
		if (buffers[0].pvBuffer != NULL)
			free(buffers[0].pvBuffer);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* destroy everything that we needed */
	NCryptDeleteKey(ncrypt_master_key, 0);
	NCryptFreeObject(prov_handle);
	if (buffers[0].pvBuffer != NULL)
		free(buffers[0].pvBuffer);

	/* Write it to the file */
	// Can we open the file?
	if ((output_file = fopen(outfile, "wb")) == NULL)
	{
		free(pkcs8_blob);
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_INVALID_FILENAME;
	}

	/* Read it into memory */
	size_t bytes_written = fwrite(pkcs8_blob, 1, pkcs8_blob_sz, output_file);
	if (bytes_written != pkcs8_blob_sz)
	{
		free(pkcs8_blob);
		BCryptDestroyKey(bcrypt_master_key);
		return AUTHME_ERR_INVALID_FILENAME;
	}

	fclose(output_file);
	free(pkcs8_blob);

	amp->amp_service_key = bcrypt_master_key;
	*out = amp;

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Load a user public key
* ---------------------------------------------------------------- */

authme_err_t
mpass_windows_load_user_public_key(mpass_handle mh, char * b64_key)
{

	unsigned char * raw_key;
	DWORD raw_key_sz;
	unsigned char * raw_key_blob;
	DWORD raw_key_blob_sz;
	unsigned char * crypt_key_blob;
	DWORD crypt_key_blob_sz;
	unsigned char * bcrypt_key_blob;
	DWORD bcrypt_key_blob_sz;
	authme_master_password_t * amp;
	BCRYPT_KEY_HANDLE bcrypt_key;
	CERT_PUBLIC_KEY_INFO *info;
	HCRYPTPROV     crypt_prov;
	HCRYPTKEY      crypt_key;
	SECURITY_STATUS sec_stat;
	NCRYPT_KEY_HANDLE ncrypt_key;
	NCRYPT_PROV_HANDLE ncrypt_prov;
	
	amp = (authme_master_password_t *)mh;

	/* Convert the incoming key to binary format */
	raw_key_sz = 0;
	if (!CryptStringToBinaryA(b64_key, 0, CRYPT_STRING_BASE64, NULL, &raw_key_sz, NULL, 0))
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	raw_key = (unsigned char *)malloc(raw_key_sz);
	if (!CryptStringToBinaryA(b64_key, 0, CRYPT_STRING_BASE64, raw_key, &raw_key_sz, NULL, 0))
	{
		free(raw_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Now decode */
	raw_key_blob_sz = 0;

	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_PUBLIC_KEY_INFO,
		raw_key,
		raw_key_sz,
		CRYPT_DECODE_NOCOPY_FLAG,
		NULL,
		&raw_key_blob_sz))
	{
		DWORD err = GetLastError(); //CRYPT_E_BAD_ENCODE
		free(raw_key);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	raw_key_blob = (unsigned char *)malloc(raw_key_blob_sz);

	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_PUBLIC_KEY_INFO,
		raw_key,
		raw_key_sz,
		CRYPT_DECODE_NOCOPY_FLAG,
		raw_key_blob,
		&raw_key_blob_sz))
	{
		free(raw_key);
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	//free(raw_key);

	/* Pass through Crypt API */

	if (!CryptAcquireContext(&crypt_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/*
	* Import the public key into raw crypto api using the context
	*/
	info = (CERT_PUBLIC_KEY_INFO *)raw_key_blob;
	crypt_key = 0;
	if (!CryptImportPublicKeyInfo(crypt_prov, X509_ASN_ENCODING, info, &crypt_key))
	{
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Export it back to a BLOB */
	if (!CryptExportKey(crypt_key, 0, PUBLICKEYBLOB, 0, NULL, &crypt_key_blob_sz))
	{
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	crypt_key_blob = (unsigned char *)malloc(crypt_key_blob_sz);
	if (!CryptExportKey(crypt_key, 0, PUBLICKEYBLOB, 0, crypt_key_blob, &crypt_key_blob_sz))
	{
		free(crypt_key_blob);
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Open the NCryptSTorageProvider */
	if (NCryptOpenStorageProvider(&ncrypt_prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		free(crypt_key_blob);
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Import it into a NCrypt key */
	if ((sec_stat = NCryptImportKey(ncrypt_prov, 0, LEGACY_RSAPUBLIC_BLOB, NULL, &ncrypt_key, crypt_key_blob, (DWORD)crypt_key_blob_sz, 0)) != ERROR_SUCCESS)
	{
		free(crypt_key_blob);
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	free(crypt_key_blob);
	/* Now have to export it into a BCrypt key */
	bcrypt_key_blob_sz = 0;
	if ((sec_stat = NCryptExportKey(ncrypt_key, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &bcrypt_key_blob_sz, 0)) != ERROR_SUCCESS)
	{
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	bcrypt_key_blob = (unsigned char *)malloc(bcrypt_key_blob_sz);
	if ((sec_stat = NCryptExportKey(ncrypt_key, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, bcrypt_key_blob, bcrypt_key_blob_sz, &bcrypt_key_blob_sz, 0)) != ERROR_SUCCESS)
	{
		free(bcrypt_key_blob);
		free(raw_key_blob);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* And import */
	if (!NT_SUCCESS(BCryptImportKeyPair(amp->amp_bcrypt_rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &bcrypt_key, bcrypt_key_blob, bcrypt_key_blob_sz, 0)))
	{
		free(bcrypt_key_blob);
		free(raw_key_blob);
		return AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
	}

	amp->amp_user_public_key = bcrypt_key;

	/* Now we free everything */
	free(bcrypt_key_blob);
	free(raw_key_blob);
	NCryptDeleteKey(ncrypt_key, 0);
	CryptDestroyKey(crypt_key);
	CryptReleaseContext(crypt_prov, 0);

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Encrypt with a randomly generated AES key and then wrap the key
* using the provided public key
* ---------------------------------------------------------------- */

unsigned char * create_symmetric_bcrypt_blob(unsigned char * key, int key_length, size_t * sz) {

	/* Build a key blob to hold an AES (or other symmetric key) blob */
	unsigned char * blob;
	BCRYPT_KEY_DATA_BLOB_HEADER * header;

	*sz = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key_length;
	
	if ((blob = (unsigned char *)malloc(*sz)) == NULL)
		return NULL;

	header = (BCRYPT_KEY_DATA_BLOB_HEADER *)blob;

	/* Set the header */
	header->cbKeyData = key_length;
	header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;

	/* Copy the key */
	memcpy(&(blob[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)]), key, key_length);
	return blob;
}

authme_err_t
mpass_windows_envelope_encrypt(mpass_handle mh, int key, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf, size_t * out_buf_len)
{
	BCRYPT_KEY_HANDLE wrap_key;
	BCRYPT_KEY_HANDLE aes_bcrypt_key;

	unsigned char * worker_buf;
	int worker_buf_len;
	unsigned char * wrap_buf;
	unsigned char * aes_blob;
	size_t aes_blob_sz;
	unsigned char aes_key[MPASS_AES_MAX_KEY_LENGTH];
	unsigned char aes_iv[MPASS_AES_IV_LENGTH];
	NTSTATUS status;
	DWORD key_buffer_sz;
	DWORD property_result, enc_sz;
	unsigned char * key_buffer;
	
	/* TODO: Really should pull the logic out of this into the general mpass code */
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	if (amp == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	/* Sanity check */
	switch (key)
	{
	case MPASS_SERVICE_PUBLIC_KEY:
		wrap_key = amp->amp_service_key;
		break;
	case MPASS_USER_PUBLIC_KEY:
		wrap_key = amp->amp_user_public_key;
		break;
	default:
		MPASS_SET_ERROR(amp, "Unknown key passed into envelope encrypt");
		return AUTHME_ERR_INVALID_KEY;
	}

	/* Allocate enough space for the AES crypto part*/
	worker_buf_len = (int)in_buf_len + MPASS_AES_BLOCK_SIZE + MPASS_AES_IV_LENGTH;
	if ((worker_buf = (unsigned char *)malloc(worker_buf_len)) == NULL)
	{
		// This would be bad!
		return AUTHME_ERR_OUT_OF_MEMORY;
	}

	// Now start creating keys and things
	if (mpass_windows_random_bytes(mh, aes_key, sizeof(aes_key)) != AUTHME_ERR_OK ||
		mpass_windows_random_bytes(mh, aes_iv, sizeof(aes_iv)) != AUTHME_ERR_OK)
	{
		// Also bad
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not generate random data for AES key and IV");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Initialise the AES component
	if ((aes_blob = create_symmetric_bcrypt_blob(aes_key, MPASS_AES_MAX_KEY_LENGTH, &aes_blob_sz)) == NULL)
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not create AES blob");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Create the key handle

	if (!NT_SUCCESS(BCryptGetProperty(amp->amp_bcrypt_aes, BCRYPT_OBJECT_LENGTH, (PUCHAR) &key_buffer_sz, sizeof(DWORD), &property_result, 0)))
	{
		free(worker_buf);
		free(aes_blob);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG (error reading properties");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	key_buffer = (unsigned char *)malloc(key_buffer_sz);
	status = BCryptImportKey(amp->amp_bcrypt_aes, 0, BCRYPT_KEY_DATA_BLOB, &aes_bcrypt_key, key_buffer, key_buffer_sz, aes_blob, (ULONG) aes_blob_sz, 0);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		free(aes_blob);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Do the encrypt */
	memcpy(worker_buf, aes_iv, MPASS_AES_IV_LENGTH);
	status = BCryptEncrypt(aes_bcrypt_key, in_buf, (ULONG) in_buf_len, NULL, aes_iv, MPASS_AES_IV_LENGTH, &worker_buf[MPASS_AES_IV_LENGTH], worker_buf_len - MPASS_AES_IV_LENGTH, &enc_sz, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		free(aes_blob);
		BCryptDestroyKey(aes_bcrypt_key);
		free(key_buffer);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Destroy the AES Bcrypt key and associated memory */
	memset(aes_blob, 0, aes_blob_sz);
	free(aes_blob);
	BCryptDestroyKey(aes_bcrypt_key);
	memset(key_buffer, 0, key_buffer_sz);
	free(key_buffer);

	worker_buf_len = MPASS_AES_IV_LENGTH + enc_sz;

	/* RSA Encrypt - start with getting the encrypt length */
	status = BCryptEncrypt(wrap_key, aes_key, MPASS_AES_MAX_KEY_LENGTH, NULL, NULL, 0, NULL, 0, &enc_sz, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}
	wrap_buf = (unsigned char *)malloc(enc_sz);

	status = BCryptEncrypt(wrap_key, aes_key, MPASS_AES_MAX_KEY_LENGTH, NULL, NULL, 0, wrap_buf, enc_sz, &enc_sz, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Done - cleanup and copy to output
	memset(aes_key, 0, sizeof(aes_key));

	*out_buf_len = 4 + (int)enc_sz + worker_buf_len;
	if ((*out_buf = (unsigned char *)malloc(*out_buf_len)) == NULL)
	{
		free(worker_buf);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, "Error allocating final buffer");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	// For our envelope, start of the buffer is always a 4 byte unsigned int
	(*out_buf)[0] = ((unsigned int)enc_sz >> 24) & 0xFF;
	(*out_buf)[1] = ((unsigned int)enc_sz >> 16) & 0xFF;
	(*out_buf)[2] = ((unsigned int)enc_sz >> 8) & 0xFF;
	(*out_buf)[3] = (unsigned int)enc_sz & 0xFF;

	// Then the wrap itself
	memcpy(&((*out_buf)[4]), wrap_buf, enc_sz);

	// then the encrypted data
	memcpy(&((*out_buf)[4 + enc_sz]), worker_buf, worker_buf_len);

	free(worker_buf);
	free(wrap_buf);

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Generate random data
* ---------------------------------------------------------------- */

authme_err_t
mpass_windows_random_bytes(mpass_handle mh, unsigned char * out, int bytes)
{

	NTSTATUS stat;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	stat = BCryptGenRandom(amp->amp_bcrypt_rng, out, bytes, 0);

	if (!NT_SUCCESS(stat))
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
mpass_windows_cipher_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out, int encrypt)
{

	BCRYPT_KEY_HANDLE aes_bcrypt_key;
	unsigned char * aes_blob;
	size_t aes_blob_sz;

	unsigned char aes_iv[MPASS_AES_IV_LENGTH];
	unsigned char in_buf[1024];
	unsigned char out_buf[1024 + MPASS_AES_BLOCK_SIZE];
	int bytes_read, i;
	int aes_iv_len;

	DWORD key_buffer_sz;
	DWORD property_result, enc_sz;
	unsigned char * key_buffer;
	NTSTATUS status;


	authme_master_password_t * amp = (authme_master_password_t *)mh;

	/* Set up the IV */
	aes_iv_len = MPASS_AES_IV_LENGTH;
	if (encrypt)
	{

		if (mpass_windows_random_bytes(mh, aes_iv, sizeof(aes_iv)) != AUTHME_ERR_OK)
		{
			// Also bad
			MPASS_SET_ERROR(amp, "Could not generate random data for bulk AES IV");
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

	// Initialise the AES component
	if ((aes_blob = create_symmetric_bcrypt_blob(key, MPASS_AES_MAX_KEY_LENGTH, &aes_blob_sz)) == NULL)
	{
		MPASS_SET_ERROR(amp, "Could not create AES blob");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Create the key handle

	if (!NT_SUCCESS(BCryptGetProperty(amp->amp_bcrypt_aes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&key_buffer_sz, sizeof(DWORD), &property_result, 0)))
	{
		free(aes_blob);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG (error reading properties");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	key_buffer = (unsigned char *)malloc(key_buffer_sz);
	status = BCryptImportKey(amp->amp_bcrypt_aes, 0, BCRYPT_KEY_DATA_BLOB, &aes_bcrypt_key, key_buffer, key_buffer_sz, aes_blob, (ULONG)aes_blob_sz, 0);
	if (!NT_SUCCESS(status))
	{
		free(aes_blob);
		free(key_buffer);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}
	memset(aes_blob, 0, aes_blob_sz);
	free(aes_blob);

	/* Now we loop */
	while (!feof(in))
	{
		DWORD flags = 0;

		bytes_read = (int)fread(in_buf, 1, 1024, in);
		enc_sz = i = 1024 + MPASS_AES_BLOCK_SIZE;
		

		if (feof(in) || bytes_read != 1024)
			flags = BCRYPT_BLOCK_PADDING;

		if (encrypt)
		{
			status = BCryptEncrypt(aes_bcrypt_key, in_buf, (ULONG)bytes_read, NULL, aes_iv, MPASS_AES_IV_LENGTH, out_buf, i, &enc_sz, flags);
		}
		else
		{
			status = BCryptDecrypt(aes_bcrypt_key, in_buf, (ULONG)bytes_read, NULL, aes_iv, MPASS_AES_IV_LENGTH, out_buf, i, &enc_sz, flags);
		}
		if (!NT_SUCCESS(status))
		{
			BCryptDestroyKey(aes_bcrypt_key);
			free(key_buffer);
			MPASS_SET_ERROR(amp, "Error during bulk file encrypt");
			return AUTHME_ERR_CRYPTO_OPERATION;
		}

		fwrite(out_buf, 1, enc_sz, out);
	}

	// Done the AES part
	BCryptDestroyKey(aes_bcrypt_key);
	free(key_buffer);

	return AUTHME_ERR_OK;


}

authme_err_t
mpass_windows_encrypt_file_to_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out)
{
	/* Simply do a cipher operation with encrypt set to 1 */
	return mpass_windows_cipher_file_to_file(mh, key, in, out, 1);
}

authme_err_t
mpass_windows_decrypt_file_from_file(mpass_handle mh, unsigned char * key, FILE * in, FILE * out)
{
	/* Simply do a cipher operation with encrypt set to 0 (derypt) */
	return mpass_windows_cipher_file_to_file(mh, key, in, out, 0);
}

/* ---------------------------------------------------------------- *
* Decrypt an envelope using our key if we have one
* ---------------------------------------------------------------- */

authme_err_t
mpass_windows_envelope_decrypt(mpass_handle mh, int key, char * in_buf, unsigned char ** out_buf, size_t * out_buf_len)
{

	BCRYPT_KEY_HANDLE wrap_key;
	BCRYPT_KEY_HANDLE aes_bcrypt_key;

	unsigned char * worker_buf;
	size_t worker_buf_len;
	unsigned char * aes_blob;
	size_t aes_blob_sz;
	unsigned char * wrap_buf;
	size_t enc_wrap_buf_len, wrap_buf_len;
	unsigned char * secret_buf;
	DWORD secret_buf_sz;
	int enc_secret_len;
	int i;
	authme_master_password_t * amp = (authme_master_password_t *)mh;

	NTSTATUS status;
	unsigned char * key_buffer;
	DWORD key_buffer_sz;
	DWORD property_result, enc_sz;

	authme_err_t err;

	if (amp == NULL)
		return AUTHME_ERR_NO_CRYPTO;

	/* For now we only know how to decrypt using the service private key */
	if (key != MPASS_SERVICE_PRIVATE_KEY)
	{
		MPASS_SET_ERROR(amp, "Can only unwrap using service private key");
		return AUTHME_ERR_INVALID_KEY;
	}

	wrap_key = amp->amp_service_key;
	if (wrap_key == NULL)
	{
		MPASS_SET_ERROR(amp, "Private key not loaded");
		return AUTHME_ERR_INVALID_KEY;
	}

	/* Decode the buffer */
	if ((err = mpass_windows_b64_decode(amp, in_buf, &worker_buf, &worker_buf_len)) != AUTHME_ERR_OK)
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
	status = BCryptDecrypt(wrap_key, &worker_buf[4], (ULONG) enc_wrap_buf_len, NULL, NULL, 0, NULL, 0, &enc_sz, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	wrap_buf = (unsigned char *)malloc(enc_sz);
	status = BCryptDecrypt(wrap_key, &worker_buf[4], (ULONG) enc_wrap_buf_len, NULL, NULL, 0, wrap_buf, enc_sz, &enc_sz, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Initial unwrap complete */
	if (enc_sz != MPASS_AES_MAX_KEY_LENGTH)
	{
		free(worker_buf);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, "Error in decrypted AES key length");
		return AUTHME_ERR_CRYPTO_OPERATION;

	}
	wrap_buf_len = enc_sz;

	/* Load the decrypt result into an AES key */
	if ((aes_blob = create_symmetric_bcrypt_blob(wrap_buf, MPASS_AES_MAX_KEY_LENGTH, &aes_blob_sz)) == NULL)
	{
		free(worker_buf);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, "Could not create AES blob");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	// Create the key handle

	if (!NT_SUCCESS(BCryptGetProperty(amp->amp_bcrypt_aes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&key_buffer_sz, sizeof(DWORD), &property_result, 0)))
	{
		free(worker_buf);
		free(aes_blob);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG (error reading properties");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	key_buffer = (unsigned char *)malloc(key_buffer_sz);
	status = BCryptImportKey(amp->amp_bcrypt_aes, 0, BCRYPT_KEY_DATA_BLOB, &aes_bcrypt_key, key_buffer, key_buffer_sz, aes_blob, (ULONG)aes_blob_sz, 0);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		free(aes_blob);
		free(wrap_buf);
		MPASS_SET_ERROR(amp, "Could not import AES key to CNG");
		return AUTHME_ERR_CRYPTO_INIT;
	}

	/* Sanity checks */
	enc_secret_len = (int)worker_buf_len - 4 - (int)enc_wrap_buf_len - MPASS_AES_IV_LENGTH;
	if (enc_secret_len <= 0)
	{
		free(worker_buf);
		free(aes_blob);
		free(wrap_buf);
		BCryptDestroyKey(aes_bcrypt_key);
		free(key_buffer);
		MPASS_SET_ERROR(amp, "Internal assertion on buffer lengths failed - help!");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	/* Everything we need loaded - so we decrypt */
	status = BCryptDecrypt(aes_bcrypt_key, &worker_buf[4 + enc_wrap_buf_len + MPASS_AES_IV_LENGTH], enc_secret_len, NULL, &worker_buf[4 + enc_wrap_buf_len], MPASS_AES_IV_LENGTH, NULL, 0, &secret_buf_sz, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		free(aes_blob);
		free(wrap_buf);
		BCryptDestroyKey(aes_bcrypt_key);
		free(key_buffer);
		MPASS_SET_ERROR(amp, "Internal assertion on buffer lengths failed - help!");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	secret_buf = (unsigned char *)malloc(secret_buf_sz);
	status = BCryptDecrypt(aes_bcrypt_key, &worker_buf[4 + enc_wrap_buf_len + MPASS_AES_IV_LENGTH], enc_secret_len, NULL, &worker_buf[4 + enc_wrap_buf_len], MPASS_AES_IV_LENGTH, secret_buf, secret_buf_sz, &secret_buf_sz, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status))
	{
		free(worker_buf);
		free(aes_blob);
		free(wrap_buf);
		BCryptDestroyKey(aes_bcrypt_key);
		free(key_buffer);
		MPASS_SET_ERROR(amp, "Internal assertion on buffer lengths failed - help!");
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	free(worker_buf);
	memset(aes_blob, 0, aes_blob_sz);
	free(aes_blob);
	memset(wrap_buf, 0, wrap_buf_len);
	free(wrap_buf);
	BCryptDestroyKey(aes_bcrypt_key);
	free(key_buffer);
	
	*out_buf_len = secret_buf_sz;
	*out_buf = secret_buf;

	return AUTHME_ERR_OK;
}


/* ---------------------------------------------------------------- *
* Base64 encode a buffer
* ---------------------------------------------------------------- */

authme_err_t
mpass_windows_b64_encode(mpass_handle mh, unsigned char * in_buf, size_t in_buf_len, unsigned char ** out_buf)
{

	unsigned char * out;
	DWORD out_buf_sz;

	out_buf_sz = 0;
	if (!CryptBinaryToStringA(in_buf, (DWORD) in_buf_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &out_buf_sz))
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	out = (unsigned char *)malloc(out_buf_sz);
	if (!CryptBinaryToStringA(in_buf, (DWORD) in_buf_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_buf_sz))
	{
		free(out);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	*out_buf = out;

	return AUTHME_ERR_OK;
}

/* ---------------------------------------------------------------- *
* Base64 decode a buffer
* ---------------------------------------------------------------- */

authme_err_t
mpass_windows_b64_decode(mpass_handle mh, char * in_b64, unsigned char ** out_buf, size_t * out_buf_len)
{

	unsigned char * out;
	DWORD out_buf_sz;

	out_buf_sz = 0;
	if (!CryptStringToBinaryA(in_b64, 0, CRYPT_STRING_BASE64, NULL, &out_buf_sz, NULL, 0))
	{
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	out = (unsigned char *)malloc(out_buf_sz);
	if (!CryptStringToBinaryA(in_b64, 0, CRYPT_STRING_BASE64, out, &out_buf_sz, NULL, 0))
	{
		free(out);
		return AUTHME_ERR_CRYPTO_OPERATION;
	}

	*out_buf = out;
	*out_buf_len = out_buf_sz;

	return AUTHME_ERR_OK;

}

/* ---------------------------------------------------------------- *
* Initialise the LSA key and save in the LSA private data area
* ---------------------------------------------------------------- */

#if defined WIN32
authme_err_t
mpass_windows_init_w32_lsa_key(authme_master_password_t ** out)
{
#if 0


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
	swprintf(pwcBuffer, bptr->length + 1, L"%.*hs", (int)bptr->length, bptr->data);

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

#endif

	return AUTHME_ERR_CRYPTO_OPERATION;


}

authme_err_t
mpass_windows_w32_load_master_password(mpass_handle * out)
{

#if 0

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

#endif

	return AUTHME_ERR_CRYPTO_OPERATION;


}

#endif

#endif /* HAVE_WINCAPI */
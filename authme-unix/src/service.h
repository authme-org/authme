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

#ifndef AUTHME_SERVICE_H
#define AUTHME_SERVICE_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUTHME_LIBRARY_VERSION "0.1.0"

#define AUTHME_SET_ERROR(X,Y) {if (X->psc_last_error != NULL) {free (X->psc_last_error) ;} X->psc_last_error = strdup(Y); }

	/* ---------------------------------------------------------------- *
	 * Service Configuration for a fixed request
	 * ---------------------------------------------------------------- */

	// We essentially use this as an opaque type.  Will allow us to switch
	// out for other crypto libraries at a later date

	typedef struct key_file_pass_s {
		int				  password_format;			/* The saved password type */
		char			* password_data;			/* A string (null terminated) containing the password */
	} key_file_pass_t;

#define AUTHME_KEY_PASS_NONE		0x00 /* No password loaded */
#define AUTHME_KEY_PASS_PLAIN		0x01 /* A plain text password */
#define AUTHME_KEY_PASS_WINPROTECT  0x02 /* A password protected using Windows Protect API */

	typedef struct authme_service_config_s {

		char			* psc_url;            /* URL of the service */
		char			* psc_check_id;       /* ID of the current check */
		char			* psc_check_url;      /* URL of the current check */
		char			* psc_user_id;        /* User ID of the current check */
		char			* psc_user_key_id;	/* Service keyID for current user */
		char			* psc_server_id;      /* ID of server making the check */
		char			* psc_nonce;          /* Current NONCE value */
		char			* psc_secret_id;      /* ID of a secret stored in service */
		char			* psc_wrapped_secret; /* Actual secret to send to service */
		unsigned char	* psc_unwrapped_secret; /* Secret returned from service*/
		size_t            psc_unwrapped_secret_len;
		char			* psc_server_string;  /* Arbitrary data from server */
		char			* psc_last_error;     /* String for last error */
		char			  psc_check_status;   /* Status of check - see below */
		char			* psc_key_file;		  /* Path to the master password file */
		key_file_pass_t   psc_key_file_pass;  /* Password to the key file */

		// Crypto implementation - opaque type to callers so we can hide
		// crypto details

		void	  * psc_mpass;

	} authme_service_config_t;

#define AUTHME_STATUS_UNDEFINED       0x00
#define AUTHME_STATUS_SUBMITTED       0x01
#define AUTHME_STATUS_APPROVED        0x02
#define AUTHME_STATUS_DECLINED        0x03

	/* Used for crypto wrappers */
#define MPASS_SERVICE_PUBLIC_KEY	  0x01
#define MPASS_USER_PUBLIC_KEY		  0x02
#define MPASS_SERVICE_PRIVATE_KEY	  0x03

	/* Define the encrypted file types */
#define AUTHME_FILE_LOCAL_KEY		  0x01		/* File was encrypted with a locally stored key */
#define AUTHME_FILE_SERVICE_KEY		  0x02		/* File was encrypted with a key stored at service */


	/* ---------------------------------------------------------------- *
	 * Service function prototypes
	 * ---------------------------------------------------------------- */

	typedef int authme_err_t;

	// Init and shutdown
	authme_err_t
		authme_service_init();
	authme_err_t
		authme_service_shutdown();

	// Configuration loading and management
	authme_service_config_t * authme_service_config_create(void);
	void authme_service_config_free(authme_service_config_t * psc);

	authme_err_t authme_get_svc_info(authme_service_config_t * psc);
	int authme_start_svc_check(authme_service_config_t * psc);
	authme_err_t authme_get_svc_check_status(authme_service_config_t * psc);
	authme_err_t authme_get_user_public_key(authme_service_config_t * psc);

	// Pass throughs to the crypto plugin
	authme_err_t authme_load_master_password(authme_service_config_t * psc, char * password);
	authme_err_t authme_generate_master_password(authme_service_config_t * psc, char * password);
	authme_err_t authme_load_user_public_key(authme_service_config_t * psc, char * b64_key);
#if defined WIN32
	authme_err_t authme_init_win32_lsa_key(authme_service_config_t * psc);
	authme_err_t authme_w32_load_master_password(authme_service_config_t * psc);
#endif

	// Encrypt a secret shared between the service and us
	authme_err_t authme_wrap_secret(authme_service_config_t * psc, unsigned char * secret, size_t secret_len, char ** wrapped_secret);

	// Store a pre-wrapped secret
	authme_err_t authme_set_secret(authme_service_config_t * psc, char * wrapped_secret);

	// A utility function
	authme_err_t authme_wrap_and_set_secret(authme_service_config_t * psc, unsigned char * secret, size_t secret_len);

	// Encrypt a file.  Stores decrypt key at the service
	authme_err_t authme_encrypt_file(authme_service_config_t * psc, char * in_file, char * out_file, char local_key);

	// Decrypt a file - pulling key from service
	authme_err_t
	authme_decrypt_file(authme_service_config_t * psc, char * in_file, char * out_file);

    // Load a configuration file
    authme_err_t
    authme_load_cnf(authme_service_config_t * psc, FILE * input_file, int flags);
    authme_err_t
    authme_load_user_cnf(authme_service_config_t *psc, char * username);
	authme_err_t
	authme_load_system_cnf(authme_service_config_t * psc, int flags);

	// What is the default name for the key file on this system?
	char * get_default_key_file_name();

	authme_err_t
	authme_save_user_cnf(authme_service_config_t * psc, int flags, char * username);

    
	/* ---------------------------------------------------------------- *
	 * Service return codes
	 * ---------------------------------------------------------------- */

#define AUTHME_ERR_OK                                0x00
#define AUTHME_ERR_INVALID_SERVICE_URL               0x01
#define AUTHME_ERR_SERVICE_CONNECT_FAILED            0x02
#define AUTHME_ERR_INVALID_PARMS                     0x03
#define AUTHME_ERR_SERVICE_RETURNED_ERR              0x04
#define AUTHME_ERR_USER_UNKNOWN                      0x05
#define AUTHME_ERR_SERVICE_ERROR                     0x06
#define AUTHME_ERR_OUT_OF_MEMORY					 0x07
#define AUTHME_ERR_INVALID_FILENAME					 0x18
#define AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY			 0x29
#define AUTHME_ERR_INVALID_KEY						 0x0A
#define AUTHME_ERR_CRYPTO_INIT						 0x0B
#define AUTHME_ERR_CRYPTO_OPERATION				     0x0C
#define AUTHME_ERR_BASE64_FAILED					 0x0D
#define AUTHME_ERR_NO_CRYPTO						 0x0E
#define AUTHME_ERR_INSUFFICIENT_PRIVS				 0x0F
#define AUTHME_ERR_FILE_READ						 0x10
#define AUTHME_ERR_REQUEST_DECLINED					 0x11
#define AUTHME_ERR_TIMEOUT							 0x12
#define AUTHME_ERR_HTTPC_INIT						 0x13
#define AUTHME_ERR_HTTPC_OPERATION					 0x14
#define AUTHME_ERR_NO_HTTPC							 0x15
#define AUTHME_ERR_HTTPC_REUSE						 0x16
#define AUTHME_ERR_HTTPC_NO_INIT					 0x17
#define AUTHME_ERR_HTTPC_CONNECT					 0x18
#define AUTHME_ERR_HTTPC_BAD_URL					 0x19
#define AUTHME_ERR_UNKNOWN_CNF_OPTION                0x20
#define AUTHME_ERR_FILE_OPEN					     0x21

    
	/* ---------------------------------------------------------------- *
	 * Configuration flags
	 * ---------------------------------------------------------------- */

#define AUTHME_CNF_IGNORE_SERVICE_URL                0x0001
#define AUTHME_CNF_IGNORE_USER_ID                    0x0002
#define AUTHME_CNF_IGNORE_KEY_FILENAME				 0x0004
#define AUTHME_CNF_IGNORE_KEY_FILE_PASS				 0x0008

#ifdef __cplusplus
}
#endif

#endif

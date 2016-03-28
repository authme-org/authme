/* AuthMeDLL.cpp
*
* Copyright 2016 Berin Lautenbach
*
* Licensed under the Apache License, Version 2.0 (the "License");
*you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#include "service.h"
}
#endif

namespace AuthMeDLL {


	public ref class AuthMe
	{

	private:

		authme_service_config_t * psc;

		/* Internal holders so we don't need to continually marshall and unmarshall strings */
		System::String ^service_url;
		System::String ^user_id;
		System::String ^key_file_name;

	public:

		/* This will create the C structures and intialise an instance of the service
		 * library.  This can then be called from the managed code
		 */

		AuthMe();
		~AuthMe();

		/* Configuration handling */
		authme_err_t loadUserCnf();
		authme_err_t saveUserCnf();

		/*---------------------------------------------------------------
		* Service Calls
		* ---------------------------------------------------------------*/

		/* Ping the service */
		System::String ^doPing(void);

		/* Retrieve a user's public key*/
		authme_err_t doLoadUserPublicKey(System::String ^user);

		/* Encrypt / Decrypt a file */
		authme_err_t doEncryptFile(System::String ^inFile, System::String ^outFile, bool local_key);
		authme_err_t doDecryptFile(System::String ^inFile, System::String ^outFile);

		/*---------------------------------------------------------------
		* setters/getters
		* ---------------------------------------------------------------*/

		/* Get the last error string */
		System::String ^AuthMe::getLastError(void);

		/* Set/Get the URL */
		void setURL(System::String ^url);
		System::String ^getURL(void);

		/* UserID */
		void setUserId(System::String ^userId);
		System::String ^getUserId(void);

		/* Loaded public key */
		System::String ^getPublicKeyId(void);

		/* Key file handling */
		void setKeyFileName(System::String ^fileName);
		System::String ^getKeyFileName(void);
		bool keyFileLoaded();
		System::String ^getDefaultKeyFileName(void);
		bool generateKeyFile(System::String ^filename, System::String ^password);

		/* Takes the raw password and then stores in psc as a protected variant */
		bool setProtectedKeyFilePassword(System::String ^password);

		/* And decrypts the master password using it */
		bool loadMasterPassword(System::String ^password, bool tryConfigPassword);

		/* Unfortunately we can't carry error codes over with #defines */
		literal int AUTHME_ERRC_OK = AUTHME_ERR_OK;
		literal int AUTHME_ERRC_INVALID_SERVICE_URL = AUTHME_ERR_INVALID_SERVICE_URL;
		literal int AUTHME_ERRC_SERVICE_CONNECT_FAILED = AUTHME_ERR_SERVICE_CONNECT_FAILED;
		literal int AUTHME_ERRC_INVALID_PARMS = AUTHME_ERR_INVALID_PARMS;
		literal int AUTHME_ERRC_SERVICE_RETURNED_ERR = AUTHME_ERR_SERVICE_RETURNED_ERR;
		literal int AUTHME_ERRC_USER_UNKNOWN = AUTHME_ERR_USER_UNKNOWN;
		literal int AUTHME_ERRC_SERVICE_ERROR = AUTHME_ERR_SERVICE_ERROR;
		literal int AUTHME_ERRC_OUT_OF_MEMORY = AUTHME_ERR_OUT_OF_MEMORY;
		literal int AUTHME_ERRC_INVALID_FILENAME = AUTHME_ERR_INVALID_FILENAME;
		literal int AUTHME_ERRC_CANNOT_LOAD_PRIVATE_KEY = AUTHME_ERR_CANNOT_LOAD_PRIVATE_KEY;
		literal int AUTHME_ERRC_INVALID_KEY = AUTHME_ERR_INVALID_KEY;
		literal int AUTHME_ERRC_CRYPTO_INIT = AUTHME_ERR_CRYPTO_INIT;
		literal int AUTHME_ERRC_CRYPTO_OPERATION = AUTHME_ERR_CRYPTO_OPERATION;
		literal int AUTHME_ERRC_BASE64_FAILED = AUTHME_ERR_BASE64_FAILED;
		literal int AUTHME_ERRC_NO_CRYPTO = AUTHME_ERR_NO_CRYPTO;
		literal int AUTHME_ERRC_INSUFFICIENT_PRIVS = AUTHME_ERR_INSUFFICIENT_PRIVS;
		literal int AUTHME_ERRC_FILE_READ = AUTHME_ERR_FILE_READ;
		literal int AUTHME_ERRC_REQUEST_DECLINED = AUTHME_ERR_REQUEST_DECLINED;
		literal int AUTHME_ERRC_TIMEOUT = AUTHME_ERR_TIMEOUT;
		literal int AUTHME_ERRC_HTTPC_INIT = AUTHME_ERR_HTTPC_INIT;
		literal int AUTHME_ERRC_HTTPC_OPERATION = AUTHME_ERR_HTTPC_OPERATION;
		literal int AUTHME_ERRC_NO_HTTPC = AUTHME_ERR_NO_HTTPC;
		literal int AUTHME_ERRC_HTTPC_REUSE = AUTHME_ERR_HTTPC_REUSE;
		literal int AUTHME_ERRC_HTTPC_NO_INIT = AUTHME_ERR_HTTPC_NO_INIT;
		literal int AUTHME_ERRC_HTTPC_CONNECT = AUTHME_ERR_HTTPC_CONNECT;
		literal int AUTHME_ERRC_HTTPC_BAD_URL = AUTHME_ERR_HTTPC_BAD_URL;
		literal int AUTHME_ERRC_UNKNOWN_CNF_OPTION = AUTHME_ERR_UNKNOWN_CNF_OPTION;
		literal int AUTHME_ERRC_FILE_OPEN = AUTHME_ERR_FILE_OPEN;
	};
}

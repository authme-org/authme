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

// This is the main DLL file.

#include "stdafx.h"

#include "AuthMeDLL.h"

#include <atlstr.h>
#include <string.h>
#include <stdlib.h>
#using <mscorlib.dll>
#using <System.Security.dll>
#include <msclr/marshal.h>


using namespace System;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Cryptography;
using namespace msclr::interop;

namespace AuthMeDLL {

/*---------------------------------------------------------------
 * Some utility functions
 * ---------------------------------------------------------------*/

	char *refToChar(String ^ from)
	{
		marshal_context ^ context = gcnew marshal_context();
		const char * intermediate = context->marshal_as<const char *>(from);
		char * ret = strdup(intermediate);
		delete(context);

		return ret;
	}

	array<Byte>^ refToByteArray(String ^from, bool include_terminator)
	{
		array<Byte> ^byteArray = System::Text::Encoding::UTF8->GetBytes(from);
		if (!include_terminator)
			return byteArray;

		array<Byte> ^withTerm = gcnew array<Byte>(byteArray->Length + 1);
		byteArray->CopyTo(withTerm, 0);
		withTerm[withTerm->Length - 1] = '\0';

		// In case it was a passsword
		for (int i = 0; i < byteArray->Length; ++i)
			byteArray[i] = '\0';

		return withTerm;
	}

	/*---------------------------------------------------------------
	* Constructors / Destructors
	* ---------------------------------------------------------------*/

	AuthMe::AuthMe()
	{

		/* init the service library */
		authme_service_init();

		/* Init the configs */
		psc = authme_service_config_create();
		psc->psc_url = strdup("http://pluto.wingsofhermes.org:8080/AuthMeWS/Svc");
	}

	AuthMe::~AuthMe()
	{

		// Shutdown
		authme_service_config_free(psc);
		authme_service_shutdown();
	}

	/*---------------------------------------------------------------
	* Service Calls
	* ---------------------------------------------------------------*/

	String ^AuthMe::doPing()
	{

		authme_err_t res;

		/* Ping the service - get a status message and return */

		res = authme_get_svc_info(psc);

		if (res == AUTHME_ERR_OK)
		{
			return gcnew String(psc->psc_last_error);
		}
		else
			return gcnew String("Error connecting to service");
	}

	authme_err_t AuthMe::doLoadUserPublicKey(String ^userId)
	{
		/* We temporarily over-ride the held public key */
		/* TODO: FIx this - it's serioulsy stupid and ugly */
		char * user_id_store = psc->psc_user_id;

		psc->psc_user_id = refToChar(userId);
		authme_err_t res = authme_get_user_public_key(psc);
		free(psc->psc_user_id);
		psc->psc_user_id = user_id_store;

		return res;
	}

	authme_err_t AuthMe::doEncryptFile(String ^inFile, String ^outFile, bool local_key)
	{
		char * in_file = refToChar(inFile);
		char * out_file = refToChar(outFile);

		char local_key_c;

		if (local_key == true)
			local_key_c = 1;
		else
			local_key_c = 0;

		return authme_encrypt_file(psc, in_file, out_file, local_key_c);
	}

	authme_err_t AuthMe::doDecryptFile(String ^inFile, String ^outFile)
	{
		char * in_file = refToChar(inFile);
		char * out_file = refToChar(outFile);

		return authme_decrypt_file(psc, in_file, out_file);
	}

	/*---------------------------------------------------------------
	* Set / Get 
	* ---------------------------------------------------------------*/

	String ^AuthMe::getLastError(void)
	{
		if (psc->psc_last_error != NULL)
			return gcnew String(psc->psc_last_error);

		return nullptr;
	}

	String ^AuthMe::getPublicKeyId(void)
	{
		if (psc->psc_user_key_id != NULL)
			return gcnew String(psc->psc_user_key_id);

		return nullptr;
	}


	void AuthMe::setURL(String ^url)
	{
		if (psc->psc_url != NULL)
			free(psc->psc_url);

		marshal_context ^ context = gcnew marshal_context();
		const char * url_str = context->marshal_as<const char *>(url);
		psc->psc_url = strdup(url_str);
		delete(context);

		/* And for the wrapper so it's easily accessible */
		this->service_url = url;
	}

	String ^AuthMe::getURL()
	{
		return service_url;
	}

	void AuthMe::setUserId(System::String ^userId) 
	{
		if (psc->psc_user_id != NULL)
			free(psc->psc_user_id);

		psc->psc_user_id = refToChar(userId);

		/* And for the wrapper so it's easily accessible */
		this->user_id = userId;

	}
	System::String ^AuthMe::getUserId(void)
	{
		return this->user_id;
	}

/*---------------------------------------------------------------
 * Key file
 * ---------------------------------------------------------------*/


	void AuthMe::setKeyFileName(System::String ^fileName)
	{
		if (psc->psc_key_file != NULL)
			free(psc->psc_key_file);

		psc->psc_key_file = refToChar(fileName);

		/* And for the wrapper so it's easily accessible */
		this->key_file_name = fileName;

	}
	System::String ^AuthMe::getKeyFileName(void)
	{
		return this->key_file_name;
	}

	bool AuthMe::keyFileLoaded(void)
	{
		return psc->psc_mpass != NULL;
	}

	String ^AuthMe::getDefaultKeyFileName(void)
	{
		return gcnew String(get_default_key_file_name());
	}

	bool AuthMe::generateKeyFile(System::String ^filename, String ^password)
	{
		char * p;
		authme_err_t err;

		this->setKeyFileName(filename);
		p = refToChar(password);

		err = authme_generate_master_password(psc, p);
		free (p);

		return (err == AUTHME_ERR_OK);
	}

	bool AuthMe::setProtectedKeyFilePassword(String ^password)
	{

		array<Byte> ^password_bytes = refToByteArray(password, true);
		array<Byte> ^encrypted_password_bytes = ProtectedData::Protect(password_bytes, nullptr, DataProtectionScope::CurrentUser);
		int output_size = ((encrypted_password_bytes->Length * 4) / 3) + (encrypted_password_bytes->Length / 96) + 12;  /* Have some extras */
		int in_offset, out_offset, input_block_size, output_block_size;

		// Now Base64 encode
		ToBase64Transform ^tb64 = gcnew ToBase64Transform();
		array<Byte> ^b64_password = gcnew array<Byte>(output_size);
		
		in_offset = 0; 
		out_offset = 0;

		input_block_size = tb64->InputBlockSize;
		output_block_size = tb64->OutputBlockSize;
		while (encrypted_password_bytes->Length - in_offset > input_block_size)
		{
			tb64->TransformBlock(
				encrypted_password_bytes,
				in_offset,
				encrypted_password_bytes->Length - in_offset,
				b64_password,
				out_offset);

			in_offset += input_block_size;
			out_offset += output_block_size;
		}
		
		array<Byte> ^final_block = tb64->TransformFinalBlock(encrypted_password_bytes, in_offset, encrypted_password_bytes->Length - in_offset);

		in_offset = 0;
		while (in_offset < final_block->Length && out_offset < b64_password->Length)
		{
			b64_password[out_offset++] = final_block[in_offset++];
		}

		b64_password[out_offset] = '\0';

		/* Copy final block into the main array */
		

		if (psc->psc_key_file_pass.password_data != NULL)
			free(psc->psc_key_file_pass.password_data);

		//psc->psc_key_file_pass.password_data = refToChar(Text::Encoding::ASCII->GetString(b64_password));
		pin_ptr<unsigned char> b64_ptr = &b64_password[0];
		psc->psc_key_file_pass.password_data = strdup((char *) b64_ptr);
		psc->psc_key_file_pass.password_format = AUTHME_KEY_PASS_WINPROTECT;

		return true;
	}

	bool AuthMe::loadMasterPassword(String ^password, bool tryConfigPassword)
	{
		/* Try the config password if it is allowed */
		if (tryConfigPassword && psc->psc_key_file_pass.password_format == AUTHME_KEY_PASS_WINPROTECT && psc->psc_key_file_pass.password_data != NULL)
		{
			FromBase64Transform ^fb64 = gcnew FromBase64Transform();
			int in_offset, out_offset, input_block_size, output_block_size;
			array<Byte> ^decoded_bytes;
			char * input_char_bytes = psc->psc_key_file_pass.password_data;
			int input_len = strlen(input_char_bytes);

			array<Byte> ^input_bytes = gcnew array<Byte>(input_len);
			Marshal::Copy((IntPtr)input_char_bytes, input_bytes, 0, input_len);

			input_block_size = fb64->InputBlockSize;
			output_block_size = fb64->OutputBlockSize;

			decoded_bytes = gcnew array<Byte>(input_len); /* Wasteful - but quick */

			in_offset = out_offset = 0;
			while (input_len - in_offset > 4)
			{
				fb64->TransformBlock(
					input_bytes,
					in_offset,
					input_len - in_offset,
					decoded_bytes,
					out_offset);

				in_offset += 4;
				out_offset += fb64->OutputBlockSize;
			}

			array<Byte> ^final_block = fb64->TransformFinalBlock(input_bytes, in_offset, input_len - in_offset);
			in_offset = 0;
			while (in_offset < final_block->Length && out_offset < decoded_bytes->Length)
			{
				decoded_bytes[out_offset++] = final_block[in_offset++];
			}
			
			/* Boy that was complicated - Now unprotect*/
			array<Byte> ^decrypted_password_bytes = ProtectedData::Unprotect(decoded_bytes, nullptr, DataProtectionScope::CurrentUser);

			pin_ptr <unsigned char> pass_ptr = &decrypted_password_bytes[0];
			char * passp = (char *)pass_ptr;

			authme_err_t err;
			if ((err = authme_load_master_password(psc, passp)) == AUTHME_ERR_OK)
				return true;
		}

		return false;
	}


/*---------------------------------------------------------------
 * Configuration file handling
 * ---------------------------------------------------------------*/

	authme_err_t AuthMe::loadUserCnf()
	{
		authme_err_t ret;
		if ((ret = authme_load_user_cnf(psc, NULL)) == AUTHME_ERR_OK)
		{
			if (psc->psc_url != NULL)
				service_url = gcnew String(psc->psc_url);
			if (psc->psc_user_id != NULL)
				user_id = gcnew String(psc->psc_user_id);
			if (psc->psc_key_file != NULL)
				key_file_name = gcnew String(psc->psc_key_file);
		}

		return ret;
	}

	authme_err_t AuthMe::saveUserCnf()
	{
		return authme_save_user_cnf(psc, 0, NULL);
	}


}
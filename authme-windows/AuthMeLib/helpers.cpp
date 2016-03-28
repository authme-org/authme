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
 * THe bulk of the code from this library is taken from the Credential
 * provider sample supplied by Microsoft.
 * The above Apache license therefore only applies to the small amount
 of code written by BFL
 */

//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.

// THIS CODE TAKEN FROM THE MICROSOFT CREDENTIAL PROVIDER SAMPLES

#include "stdafx.h"

#include "helpers.h"
#include <intsafe.h>
#include <wincred.h>
#include <wincrypt.h>
#include "logging.h"
#include "utils.h"

#include <NTSecAPI.h>

// 
// Copies the field descriptor pointed to by rcpfd into a buffer allocated 
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
// 
HRESULT FieldDescriptorCoAllocCopy(
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
	)
{
	HRESULT hr;
	DWORD cbStruct = sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);

	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
		(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);

	if (pcpfd)
	{
		pcpfd->dwFieldID = rcpfd.dwFieldID;
		pcpfd->cpft = rcpfd.cpft;

		if (rcpfd.pszLabel)
		{
			hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
		}
		else
		{
			pcpfd->pszLabel = NULL;
			hr = S_OK;
		}
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}
	if (SUCCEEDED(hr))
	{
		*ppcpfd = pcpfd;
	}
	else
	{
		CoTaskMemFree(pcpfd);
		*ppcpfd = NULL;
	}


	return hr;
}

//
// Coppies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for 
// pcpfd->pszLabel.
//
HRESULT FieldDescriptorCopy(
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
	)
{
	HRESULT hr;
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

	cpfd.dwFieldID = rcpfd.dwFieldID;
	cpfd.cpft = rcpfd.cpft;

	if (rcpfd.pszLabel)
	{
		hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
	}
	else
	{
		cpfd.pszLabel = NULL;
		hr = S_OK;
	}

	if (SUCCEEDED(hr))
	{
		*pcpfd = cpfd;
	}

	return hr;
}

//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT UnicodeStringInitWithString(
	PWSTR pwz,
	UNICODE_STRING* pus
	)
{
	HRESULT hr;
	if (pwz)
	{
		size_t lenString;
		hr = StringCchLengthW(pwz, USHORT_MAX, &(lenString));

		if (SUCCEEDED(hr))
		{
			USHORT usCharCount;
			hr = SizeTToUShort(lenString, &usCharCount);
			if (SUCCEEDED(hr))
			{
				USHORT usSize;
				hr = SizeTToUShort(sizeof(WCHAR), &usSize);
				if (SUCCEEDED(hr))
				{
					hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
					if (SUCCEEDED(hr))
					{
						pus->MaximumLength = pus->Length;
						pus->Buffer = pwz;
						hr = S_OK;
					}
					else
					{
						hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
					}
				}
			}
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}
	return hr;
}

//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect 
// its limitations.
// You can read more about the UNICODE_STRING type at:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/unicode_string.asp
//
void _UnicodeStringPackedUnicodeStringCopy(
	const UNICODE_STRING& rus,
	PWSTR pwzBuffer,
	UNICODE_STRING* pus
	)
{
	pus->Length = rus.Length;
	pus->MaximumLength = rus.Length;
	pus->Buffer = pwzBuffer;

	CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// Initialize the members of a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.  
//
// The password is stored in encrypted form for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
// because the system can accept encrypted credentials.  It is not encrypted in CPUS_CREDUI
// because we cannot know whether our caller can accept encrypted credentials.
//
HRESULT KerbInteractiveUnlockLogonInit(
	PWSTR pwzDomain,
	PWSTR pwzUsername,
	PWSTR pwzPassword,
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
	)
{
	KERB_INTERACTIVE_UNLOCK_LOGON kiul;
	ZeroMemory(&kiul, sizeof(kiul));

	KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

	// Note: this method uses custom logic to pack a KERB_INTERACTIVE_UNLOCK_LOGON with a
	// serialized credential.  We could replace the calls to UnicodeStringInitWithString
	// and KerbInteractiveUnlockLogonPack with a single cal to CredPackAuthenticationBuffer,
	// but that API has a drawback: it returns a KERB_INTERACTIVE_UNLOCK_LOGON whose
	// MessageType is always KerbInteractiveLogon.  
	//
	// If we only handled CPUS_LOGON, this drawback would not be a problem.  For 
	// CPUS_UNLOCK_WORKSTATION, we could cast the output buffer of CredPackAuthenticationBuffer
	// to KERB_INTERACTIVE_UNLOCK_LOGON and modify the MessageType to KerbWorkstationUnlockLogon,
	// but such a cast would be unsupported -- the output format of CredPackAuthenticationBuffer
	// is not officially documented.

	// Initialize the UNICODE_STRINGS to share our username and password strings.
	HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);

	if (SUCCEEDED(hr))
	{
		hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);

		if (SUCCEEDED(hr))
		{
			if (SUCCEEDED(hr))
			{
				hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
			}

			if (SUCCEEDED(hr))
			{
				// Set a MessageType based on the usage scenario.
				switch (cpus)
				{
				case CPUS_UNLOCK_WORKSTATION:
					pkil->MessageType = KerbWorkstationUnlockLogon;
					hr = S_OK;
					break;

				case CPUS_LOGON:
					pkil->MessageType = KerbInteractiveLogon;
					hr = S_OK;
					break;

				case CPUS_CREDUI:
					pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0; // MessageType does not apply to CredUI
					hr = S_OK;
					break;

				default:
					hr = E_FAIL;
					break;
				}

				if (SUCCEEDED(hr))
				{
					// KERB_INTERACTIVE_UNLOCK_LOGON is just a series of structures.  A
					// flat copy will properly initialize the output parameter.
					CopyMemory(pkiul, &kiul, sizeof(*pkiul));
				}
			}
		}
	}

	return hr;
}


//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
// 
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT KerbInteractiveUnlockLogonPack(
	const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	BYTE** prgb,
	DWORD* pcb
	)
{
	HRESULT hr;

	const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

	// alloc space for struct plus extra for the three strings
	DWORD cb = sizeof(rkiulIn) +
		pkilIn->LogonDomainName.Length +
		pkilIn->UserName.Length +
		pkilIn->Password.Length;

	KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

	if (pkiulOut)
	{
		ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

		//
		// point pbBuffer at the beginning of the extra space
		//
		BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

		//
		// set up the Logon structure within the KERB_INTERACTIVE_UNLOCK_LOGON
		//
		KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

		pkilOut->MessageType = pkilIn->MessageType;

		//
		// copy each string,
		// fix up appropriate buffer pointer to be offset,
		// advance buffer pointer over copied characters in extra space
		//
		_UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
		pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
		pbBuffer += pkilOut->LogonDomainName.Length;

		_UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
		pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
		pbBuffer += pkilOut->UserName.Length;

		_UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
		pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

		*prgb = (BYTE*)pkiulOut;
		*pcb = cb;

		hr = S_OK;
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

// 
// Unpack a KERB_INTERACTIVE_UNLOCK_LOGON *in place*.  That is, reset the Buffers from being offsets to
// being real pointers.  This means, of course, that passing the resultant struct across any sort of 
// memory space boundary is not going to work -- repack it if necessary!
//
void KerbInteractiveUnlockLogonUnpackInPlace(
	__inout_bcount(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
	)
{
	KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

	pkil->LogonDomainName.Buffer = pkil->LogonDomainName.Buffer
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->LogonDomainName.Buffer)
		: NULL;

	pkil->UserName.Buffer = pkil->UserName.Buffer
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->UserName.Buffer)
		: NULL;

	pkil->Password.Buffer = pkil->Password.Buffer
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->Password.Buffer)
		: NULL;
}

// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString)
{
	size_t cchLength;
	HRESULT hr = StringCchLengthA(pszSourceString, USHORT_MAX, &cchLength);
	if (SUCCEEDED(hr))
	{
		USHORT usLength;
		hr = SizeTToUShort(cchLength, &usLength);

		if (SUCCEEDED(hr))
		{
			pszDestinationString->Buffer = (PCHAR)pszSourceString;
			pszDestinationString->Length = usLength;
			pszDestinationString->MaximumLength = pszDestinationString->Length + 1;
			hr = S_OK;
		}
	}
	return hr;
}

// 
// Similar for a UNICODE version of an LSA string
//

HRESULT LsaInitUnicodeString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return S_FALSE;

	if (NULL != pwszString)
	{
		dwLen = (DWORD) wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return S_FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return S_OK;
}


//
// Retrieves the 'negotiate' AuthPackage from the LSA. In this case, Kerberos
// For more information on auth packages see this msdn page:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/msv1_0_lm20_logon.asp
//
HRESULT RetrieveAuthPackage(ULONG * pulAuthPackage, PSTR pAuthPackageName)
{
	HRESULT hr;
	HANDLE hLsa;

	NTSTATUS status = LsaConnectUntrusted(&hLsa);
	if (SUCCEEDED(HRESULT_FROM_NT(status)))
	{

		ULONG ulAuthPackage;
		LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, pAuthPackageName);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (SUCCEEDED(HRESULT_FROM_NT(status)))
		{
			authme_log("Auth package = %lu", ulAuthPackage);
			*pulAuthPackage = ulAuthPackage;
			hr = S_OK;
		}
		else
		{
			hr = HRESULT_FROM_NT(status);
		}
		LsaDeregisterLogonProcess(hLsa);
	}
	else
	{
		hr = HRESULT_FROM_NT(status);
	}

	return hr;
}

HRESULT RetrieveAuthMeAuthPackage(ULONG * pulAuthPackage)
{
	return RetrieveAuthPackage(pulAuthPackage, AUTHME_LSA_NAME);
}

HRESULT RetrieveNegotiateAuthPackage(ULONG * pulAuthPackage)
{
	return RetrieveAuthPackage(pulAuthPackage, NEGOSSP_NAME_A);
}
//
// Return a copy of pwzToProtect encrypted with the CredProtect API.
//
// pwzToProtect must not be NULL or the empty string.
//
static HRESULT ProtectAndCopyString(
	PWSTR pwzToProtect,
	PWSTR* ppwzProtected
	)
{
	*ppwzProtected = NULL;

	HRESULT hr = E_FAIL;

	// The first call to CredProtect determines the length of the encrypted string.
	// Because we pass a NULL output buffer, we expect the call to fail.
	//
	// Note that the third parameter to CredProtect, the number of characters of pwzToProtect
	// to encrypt, must include the NULL terminator!
	DWORD cchProtected = 0;
	if (!CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect) + 1, NULL, &cchProtected, NULL))
	{
		DWORD dwErr = GetLastError();

		if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
		{
			// Allocate a buffer long enough for the encrypted string.
			PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));

			if (pwzProtected)
			{
				// The second call to CredProtect actually encrypts the string.
				if (CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect) + 1, pwzProtected, &cchProtected, NULL))
				{
					*ppwzProtected = pwzProtected;
					hr = S_OK;
				}
				else
				{
					CoTaskMemFree(pwzProtected);

					dwErr = GetLastError();
					hr = HRESULT_FROM_WIN32(dwErr);
				}
			}
			else
			{
				hr = E_OUTOFMEMORY;
			}
		}
		else
		{
			hr = HRESULT_FROM_WIN32(dwErr);
		}
	}

	return hr;
}

//
// If pwzPassword should be encrypted, return a copy encrypted with CredProtect.
// 
// If not, just return a copy.
//
HRESULT ProtectIfNecessaryAndCopyPassword(
	PWSTR pwzPassword,
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	PWSTR* ppwzProtectedPassword
	)
{
	*ppwzProtectedPassword = NULL;

	HRESULT hr;

	// ProtectAndCopyString is intended for non-empty strings only.  Empty passwords
	// do not need to be encrypted.
	if (pwzPassword && *pwzPassword)
	{
		bool bCredAlreadyEncrypted = false;
		CRED_PROTECTION_TYPE protectionType;

		// If the password is already encrypted, we should not encrypt it again.
		// An encrypted password may be received through SetSerialization in the 
		// CPUS_LOGON scenario during a Terminal Services connection, for instance.
		if (CredIsProtectedW(pwzPassword, &protectionType))
		{
			if (CredUnprotected != protectionType)
			{
				bCredAlreadyEncrypted = true;
			}
		}

		// Passwords should not be encrypted in the CPUS_CREDUI scenario.  We
		// cannot know if our caller expects or can handle an encryped password.
		if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted)
		{
			hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
		}
		else
		{
			hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
		}
	}
	else
	{
		hr = SHStrDupW(L"", ppwzProtectedPassword);
	}

	return hr;
}

/*
 Generate a challenge string using the Windows crypto API

 Passed in buffer needs to be at minimum length + 1 bytes
 to allow for the terminating null
*/

BOOLEAN 
GenerateAuthMeChallenge(PSTR pszBuffer, size_t length) {

	BOOLEAN status = FALSE;

	// Generate some random
	static char* validCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t szValidCharacters = strlen(validCharacters);

	// Get the crypto context
	HCRYPTPROV hProvider = 0;

	if (!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		// This is not good
		return FALSE;
	}

	BYTE * pbBuffer = NULL;

	// Create a temporary buffer
	if ((pbBuffer = (BYTE *)malloc(length)) != NULL)
	{
		if (CryptGenRandom(hProvider, (DWORD) length, pbBuffer))
		{
			int i;
			for (i = 0; i < length; ++i)
			{
				unsigned char index = pbBuffer[i] % szValidCharacters;
				if (index < 0)
					index *= -1;
				pszBuffer[i] = validCharacters[index];
			}

			pszBuffer[i] = '\0';
			status = TRUE;
		}

		free(pbBuffer);
	}

	if (!CryptReleaseContext(hProvider, 0))
	{
		status = FALSE;
	}

	return status;
}

PWSTR strToWStrDup(char * input) {

	PWSTR output;
	int sz = MultiByteToWideChar(CP_ACP, 0, input, -1, NULL, 0);
	if (sz <= 0)
		return NULL;

	output = (PWSTR)malloc(sizeof(WCHAR) * sz);
	MultiByteToWideChar(CP_ACP, 0, input, -1, output, sz);

	return output;
}

char * wStrToStrDupN(LPCWSTR input, size_t count)
{

	char * output;

	int sz = WideCharToMultiByte(CP_ACP, 0, input, (int) count, NULL, 0, NULL, NULL);
	if (sz <= 0)
		return NULL;

	output = (char *)malloc(sz + 1);
	memset(output, 0, sz + 1);

	sz = WideCharToMultiByte(CP_ACP, 0, input, (int) count, output, sz, NULL, NULL);
	if (sz <= 0)
	{
		free (output);
		return NULL;
	}

	return output;
}
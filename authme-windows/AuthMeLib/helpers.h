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

// Above copyright is for the small amount of code added by BFL

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

// MUCH OF THIS CODE TAKEN FROM THE MICROSOFT CREDENTIAL PROVIDER SAMPLES

#pragma once

#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <windows.h>
#endif

#include <credentialprovider.h>
#include <NTSecAPI.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif


#ifdef __cplusplus

// Helper function - DO NOT USE OUTSIDE THIS LIBRARY
void _UnicodeStringPackedUnicodeStringCopy(
	const UNICODE_STRING& rus,
	PWSTR pwzBuffer,
	UNICODE_STRING* pus
	);

//makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
	);

//makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
	);

//packages the credentials into the buffer that the system expects
HRESULT KerbInteractiveUnlockLogonPack(
	const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	BYTE** prgb,
	DWORD* pcb
	);

#endif

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
	PWSTR pwz,
	UNICODE_STRING* pus
	);

// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
EXTERNC HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString);
EXTERNC HRESULT LsaInitUnicodeString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);

//initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
HRESULT KerbInteractiveUnlockLogonInit(
	PWSTR pwzDomain,
	PWSTR pwzUsername,
	PWSTR pwzPassword,
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
	);

//unpackages the "packed" version of the creds in-place into the "unpacked" version
void KerbInteractiveUnlockLogonUnpackInPlace(
	KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
	);


//get the Kerberos package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
	ULONG * pulAuthPackage
	);

// Check to see if the AuthMe package is loaded and get it if it is
HRESULT RetrieveAuthMeAuthPackage(
	ULONG * pulAuthPackage
	);


//encrypt a password (if necessary) and copy it; if not, just copy it
HRESULT ProtectIfNecessaryAndCopyPassword(
	PWSTR pwzPassword,
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	PWSTR* ppwzProtectedPassword
	);

BOOLEAN GenerateAuthMeChallenge(
	PSTR pszBuffer,
	size_t length
	);

/*---------------------------------------------------------------
* Some useful Windows utils
* ---------------------------------------------------------------*/

/* Convert a C string to a wide char Windows string, allocating memory for it */
EXTERNC	PWSTR strToWStrDup(char * input);
EXTERNC char * wStrToStrDupN(LPCWSTR input, size_t count);

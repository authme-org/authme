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
* NOTE:  Much of this code is taken from the Microsoft Credential Provider
* samples.This contains the following copyright statement :
*
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
*
* The Apache license therefore only applies to the small amount of code
* added by me.
*/

#include "stdafx.h"
#include "AuthMeWindows.h"
#include "helpers.h"

#include <objbase.h>

HRESULT AuthMeInteractiveUnlockLogonPack(
	const AUTHME_INTERACTIVE_UNLOCK_LOGON& ramiulIn,
	BYTE** prgb,
	DWORD* pcb
	)
{
	HRESULT hr;

	const KERB_INTERACTIVE_LOGON* pkilIn = & ramiulIn.KerbUnlockLogon.Logon;

	// alloc space for struct plus extra for the three strings
	DWORD cb = sizeof(ramiulIn) +
		pkilIn->LogonDomainName.Length +
		pkilIn->UserName.Length +
		pkilIn->Password.Length +
		ramiulIn.Verifier.Length;

	AUTHME_INTERACTIVE_UNLOCK_LOGON * pamiulOut = (AUTHME_INTERACTIVE_UNLOCK_LOGON *)CoTaskMemAlloc(cb);
	KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = &(pamiulOut->KerbUnlockLogon);

	if (pamiulOut)
	{
		ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

		//
		// point pbBuffer at the beginning of the extra space
		//
		BYTE* pbBuffer = (BYTE*)pamiulOut + sizeof(*pamiulOut);

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
		pbBuffer += pkilOut->Password.Length;

		// Add the verifier
		_UnicodeStringPackedUnicodeStringCopy(ramiulIn.Verifier, (PWSTR)pbBuffer, &pamiulOut->Verifier);
		pamiulOut->Verifier.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

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

// Much of the logic here taken from the Microsoft cred provider samples.
// We use the same kinds of structures to allow us to pass appropriate parts
// of hte buffers straight into Microsoft auth routines

HRESULT AuthMeInteractiveUnlockLogonInit(
	PWSTR pwzDomain,
	PWSTR pwzUsername,
	PWSTR pwzPassword,
	PWSTR pwzVerifier,
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	AUTHME_INTERACTIVE_UNLOCK_LOGON * paiul
	)
{
	AUTHME_INTERACTIVE_UNLOCK_LOGON aiul;
	ZeroMemory(&aiul, sizeof(aiul));

	KERB_INTERACTIVE_LOGON* pkil = &aiul.KerbUnlockLogon.Logon;

	HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);

	if (SUCCEEDED(hr))
	{
		hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);

		if (SUCCEEDED(hr))
		{
			if (SUCCEEDED(hr))
			{
				hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);

				// Out bit - add the verifier
				if (SUCCEEDED(hr))
				{
					hr = UnicodeStringInitWithString(pwzVerifier, &aiul.Verifier);
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
						pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0; // MessageType does not apply 
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
						CopyMemory(paiul, &aiul, sizeof(*paiul));
					}
				}
			}
		}
	}
	return hr;
}
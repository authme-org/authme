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

/* Much of this code heavily based on samples provided by Microsoft
 * for LSA and CP modules
 */

/*---------------------------------------------------------------
* Structures and functions used by Windows components
* ---------------------------------------------------------------*/

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <NTSecAPI.h>
#include <credentialprovider.h>

#include "helpers.h"

/*---------------------------------------------------------------
* Logon/Unlock information
* ---------------------------------------------------------------*/

 typedef enum _AUTHME_LOGON_SUBMIT_TYPE {
	AuthMeInteractiveLogon = 2,
} AUTHME_LOGON_SUBMIT_TYPE, *PAUTHME_LOGON_SUBMIT_TYPE;

 typedef struct _AUTHME_INTERACTIVE_UNLOCK_LOGON {
	 KERB_INTERACTIVE_UNLOCK_LOGON KerbUnlockLogon;
	 UNICODE_STRING Verifier;
 } AUTHME_INTERACTIVE_UNLOCK_LOGON, *PAUTHME_INTERACTIVE_UNLOCK_LOGON;


 //initializes a AUTHME_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
 HRESULT AuthMeInteractiveUnlockLogonInit(
	 PWSTR pwzDomain,
	 PWSTR pwzUsername,
	 PWSTR pwzPassword,
	 PWSTR pwzVerifier,
	 CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	 AUTHME_INTERACTIVE_UNLOCK_LOGON* paiul
	 );

#if defined __cplusplus
 // Pack the structure into local memory references only
 HRESULT AuthMeInteractiveUnlockLogonPack(
	 const AUTHME_INTERACTIVE_UNLOCK_LOGON& ramiulIn,
	 BYTE** prgb,
	 DWORD* pcb
	 );
#endif

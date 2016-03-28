/*
* Copyright 2015 Berin Lautenbach
*
*    Licensed under the Apache License, Version 2.0 (the "License");
*    you may not use this file except in compliance with the License.
*    You may obtain a copy of the License at
*
*        http://www.apache.org/licenses/LICENSE-2.0
*
*    Unless required by applicable law or agreed to in writing, software
*    distributed under the License is distributed on an "AS IS" BASIS,
*    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*    See the License for the specific language governing permissions and
*    limitations under the License.
*/

/*
* This is a very simple logging capability used to drop log entries
* into a text file to enable tracing.
*/

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4996)

#define WINVER 0x0600

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

// Other useful files
#include <strsafe.h>

#include "logging.h"

static HANDLE fh = INVALID_HANDLE_VALUE;

char * months[] = {
	"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
};

// We hold the critical section here
PCRITICAL_SECTION pDllCriticalSection = NULL;


/*
* Open the log file
*/

BOOLEAN
authme_open_log(PCRITICAL_SECTION pDllLogCriticalSection, PWSTR filename)
{

	/* ALready open? */
	if (fh != INVALID_HANDLE_VALUE)
		return TRUE;

	/* Keep appending */
	fh = CreateFile(filename,
		FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
		NULL);

	if (fh == INVALID_HANDLE_VALUE)
		return FALSE;

	/* The critical section we will use to keep our log sane */
	pDllCriticalSection = pDllLogCriticalSection;

	authme_log("Log opening");
	return TRUE;

}

/*
* Close the log
*/

BOOLEAN
authme_close_log(void)
{

	if (fh == INVALID_HANDLE_VALUE)
		return TRUE;

	authme_log("Closing log");
	CloseHandle(fh);
	fh = INVALID_HANDLE_VALUE;

	return TRUE;

}
/*
* Create a log entry in our logfile
*/

int
authme_log(const char *format, ...)
{
	char bufTime[256];
	char buf[2048];
	DWORD wr;
	DWORD ret;
	va_list ap;
	SYSTEMTIME systemTime;

	if (fh == INVALID_HANDLE_VALUE)
		return 0;

#if 1
	va_start(ap, format);
	StringCbVPrintfA(buf, 2047, format, ap);
	va_end(ap);
#endif

	/* Get Current time and output to log */
	GetLocalTime(&systemTime);
	StringCbPrintfA(bufTime, 255, "[%02d-%03s-%04d %02d:%02d:%02d] ",
		systemTime.wDay,
		months[systemTime.wMonth - 1],
		systemTime.wYear,
		systemTime.wHour,
		systemTime.wMinute,
		systemTime.wSecond
		);

	for (ret = 0; ret < 256 && format[ret] != '\0'; ++ret);

	// Don't allow log entries to interleave
	EnterCriticalSection(pDllCriticalSection);
	WriteFile(fh, bufTime, (DWORD)strlen(bufTime), &wr, NULL);
	WriteFile(fh, buf, (DWORD)strlen(buf), &wr, NULL);
	WriteFile(fh, "\r\n", 2, &wr, NULL);
	LeaveCriticalSection(pDllCriticalSection);

	return wr;
}


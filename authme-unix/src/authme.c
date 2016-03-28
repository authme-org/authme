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

#include "service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined WIN32
#	include "stdafx.h"
#	include <Windows.h>
#	define strcasecmp _stricmp
#else
#	include "config.h"
#	include <curl/curl.h>
#	include <strings.h>
#endif

#if defined (_DEBUG) && defined (_MSC_VER)
#   include <crtdbg.h>
#   include <errno.h>
#endif

/*
 * This is the "command line" version of the code.  It can do most things that the PAM module etc. can do.
 *
 * It's also very useful for testing.
 *
 * Test decrypt:
 * authme decrypt --localkey -k authme.pk8.raw --out test.file.dec --in test.file.enc -r http://pluto.wingsofhermes.org:8080/AuthMeWS/Svc -c 3b8c746e-3b50-4780-93a7-7bc60235badc -u berin-test@wingsofhermes.org -p -s serverid -u berin-test@wingsofhermes.org
 */

/* ---------------------------------------------------------------- *
 * Print Usage
 * ---------------------------------------------------------------- */

void printUsage(char * progName)
{

	fprintf(stderr, "Usage: %s ping|check|status|addsecret|encrypt|decrypt|keygen|version", progName);
#if defined WIN32
	fprintf(stderr, "|lsa-init");
#endif
	fprintf(stderr, " [options]\n\n"); 
    fprintf(stderr, "   Where options are:\n\n");
    fprintf(stderr, "    --help/-h\n");
    fprintf(stderr, "         This help message\n");
    fprintf(stderr, "    --config-file/-f\n");
    fprintf(stderr, "         Config file to load\n");
#if !defined W32
    fprintf(stderr, "           defaults to /etc/authme/authme.cnf and\n");
    fprintf(stderr, "           ~/.authme\n");
#endif
    fprintf(stderr, "    --service-url/-r\n");
    fprintf(stderr, "         Base URL of the Authme service\n");
    fprintf(stderr, "    --userid/-u\n");
    fprintf(stderr, "         User ID of user to check\n");
    fprintf(stderr, "    --serverid/-s\n");
    fprintf(stderr, "         Server ID to send to service\n");
    fprintf(stderr, "    --message/-m\n");
    fprintf(stderr, "         message to send with auth\n");
    fprintf(stderr, "    --checkid/-c\n");
    fprintf(stderr, "         Check ID to send to service\n");
	fprintf(stderr, "    --key/-k\n");
	fprintf(stderr, "         File containing our service key\n");
	fprintf(stderr, "    --print-secret/-p\n");
	fprintf(stderr, "         Print unwrapped secret from status return\n");
	fprintf(stderr, "    --password\n");
	fprintf(stderr, "         Password to be used to encrypt or decrypt the keyfile\n");
	fprintf(stderr, "    --secret-id/-i\n");
	fprintf(stderr, "         Request unwrapped secret in check\n");
	fprintf(stderr, "    --in\n");
	fprintf(stderr, "         File to use as input\n");
	fprintf(stderr, "    --out\n");
	fprintf(stderr, "         File to use as output\n");
	fprintf(stderr, "    --localkey\n");
	fprintf(stderr, "         Store wrapped key locally when encrypting\n");

#if defined WIN32
	fprintf(stderr, "    --lsa-key/-l\n");
	fprintf(stderr, "         Use the Windows LSA keystore (requires admin)\n");
#endif

}

/* ---------------------------------------------------------------- *
 * Check
 * ---------------------------------------------------------------- */

int
do_check(authme_service_config_t * psc)
{
	authme_err_t err;

    /* Check for necessary info */
    if (psc->psc_url == NULL)
    {
        fprintf(stderr, "check command requires URL\n");
        return -1;
    }

    if (psc->psc_user_id == NULL)
    {
        fprintf(stderr, "check command requires User ID\n");
        return -1;
    }

    if (psc->psc_server_id == NULL)
    {
        fprintf(stderr, "check command requires Server ID\n");
        return -1;
    }

    /* Execute */
    err = authme_start_svc_check(psc);

    if (err == AUTHME_ERR_SERVICE_CONNECT_FAILED)
        printf("Error connecting to service: %s\n", psc->psc_last_error);
    else if (err == AUTHME_ERR_OK)
        printf("Check loaded - ID = %s\n", psc->psc_check_id);
    else if (err == AUTHME_ERR_USER_UNKNOWN)
        printf("Unknown user ID from service\n");
    else
        printf("Error - %s\n", psc->psc_last_error);

    return 0;
}

int
do_status(authme_service_config_t * psc, int do_print_secret)
{

    authme_err_t err;

    /* Check for necessary info */
    if (psc->psc_url == NULL)
    {
        fprintf(stderr, "status command requires URL\n");
        return -1;
    }

    if (psc->psc_check_id == NULL)
    {
        fprintf(stderr, "status command requires Check ID\n");
        return -1;
    }

    /* Execute */
    err = authme_get_svc_check_status(psc);

    if (err == AUTHME_ERR_SERVICE_CONNECT_FAILED)
        printf("Error connecting to service: %s\n", psc->psc_last_error);
    else if (err == AUTHME_ERR_OK) {
        printf("Status check succeeded - response = ");
		if (psc->psc_check_status == AUTHME_STATUS_APPROVED)
		{
			printf("Approved\n");
			if (do_print_secret)
			{
				if (psc->psc_unwrapped_secret != NULL)
				{
					printf("Secret: %.*s\n", (int) psc->psc_unwrapped_secret_len, psc->psc_unwrapped_secret);
				}
				else
				{
					printf("No Secret returned or decrypted");
				}
			}
		}
        else if (psc->psc_check_status == AUTHME_STATUS_DECLINED)
            printf("Declined\n");
        else if (psc->psc_check_status == AUTHME_STATUS_SUBMITTED)
            printf("Submitted - no action taken\n");
        else
            printf("Undefined %d\n", psc->psc_check_status);
    }
    else if (err == AUTHME_ERR_USER_UNKNOWN)
        printf("Unknown user ID from service\n");
    else
        printf("Error - %s\n", psc->psc_last_error);

    return 0;
}

/* ---------------------------------------------------------------- *
* Add Secret
* ---------------------------------------------------------------- */

int
do_add_secret(authme_service_config_t * psc)
{
	authme_err_t res;
	char inbuf[2048];
	size_t inbuf_len;

	/* Check for necessary info */
	if (psc->psc_url == NULL)
	{
		fprintf(stderr, "Service URL required for adding secrets\n");
		return -1;
	}

	/* Can we load the service key with what we have? */
	if (authme_load_master_password(psc, NULL) != AUTHME_ERR_OK)
	{
		fprintf(stderr, "Error loading keyfile");
		return -3;
	}


	/* Read the secret - simple for now */
	printf("Enter secret: ");
	fgets(inbuf, 2047, stdin);
	inbuf_len = strlen(inbuf);

	if (inbuf_len < 2)
	{
		fprintf(stderr, "Secret must be longer than 0 characters");
		return -2;
	}

	// Strip trailing \n
	if (inbuf[inbuf_len - 1] == '\n')
		inbuf[--inbuf_len] = '\0';

	printf("Secret is: (%s)\n", inbuf);

	/* Ping the service - get a status message and return */

	res = authme_get_user_public_key(psc);

	if (res == AUTHME_ERR_OK)
	{
		printf("Obtained user public key.  KeyId = %s\n",
			psc->psc_user_key_id);
	}
	else
	{
		printf("Error: %s\n", psc->psc_last_error);
		return -2;
	}

	if (res != AUTHME_ERR_OK)
	{
		printf("Error loading public key: %s\n", psc->psc_last_error);
	}

	/* Now set the shared secret */
	res = authme_wrap_and_set_secret(psc, inbuf, inbuf_len +1);
	if (res != AUTHME_ERR_OK)
	{
		printf("Error in setting shared secret: %s\n", psc->psc_last_error);
	}

	printf("Blob stored.  Blob ID = %s\n", psc->psc_secret_id);

	return 0;
}

/* ---------------------------------------------------------------- *
* LSA Initialise
* ---------------------------------------------------------------- */

/* This only works for Windows */
#if defined WIN32

int
do_lsa_init(authme_service_config_t * psc)
{
	authme_err_t res;

	/* Check for necessary info */
	res = authme_init_win32_lsa_key(psc);

	if (res == AUTHME_ERR_OK)
	{
		printf("Initialisation success\n");
		return 0;
	}
	else
		printf("Error: %s\n", psc->psc_last_error);

	return -2;
}

#endif

/* ---------------------------------------------------------------- *
* Encrypt / Decrypt files
* ---------------------------------------------------------------- */

int
do_encrypt(authme_service_config_t * psc, char * in_file, char * out_file, char * password, char local_key)
{
	authme_err_t res;

	/* Check for necessary info */
	if (in_file == NULL || out_file == NULL)
	{
		fprintf(stderr, "Input and output filenames must be defined\n");
		return -1;
	}

	if (psc->psc_url == NULL)
	{
		fprintf(stderr, "Service URL required for adding secrets\n");
		return -1;
	}

	/* Can we load the service key with what we have? */
	if (authme_load_master_password(psc, password) != AUTHME_ERR_OK)
	{
		fprintf(stderr, "Error loading keyfile\n");
		return -3;
	}


	if (psc->psc_user_id == NULL)
	{
		fprintf(stderr, "User ID must be defined");
		return -1;
	}

	res = authme_get_user_public_key(psc);

	if (res == AUTHME_ERR_OK)
	{
		printf("Obtained user public key.  KeyId = %s\n",
			psc->psc_user_key_id);
	}
	else
	{
		printf("Error: %s\n", psc->psc_last_error);
		return -2;
	}

	res = authme_encrypt_file(psc, in_file, out_file, local_key);

	if (res != AUTHME_ERR_OK)
	{
		fprintf(stderr, "Error: %s\n", psc->psc_last_error);
		return -2;
	}

	fprintf(stderr, "Encrypt done\n");

	return 0;
}

int
do_decrypt(authme_service_config_t * psc, char * in_file, char * password, char * out_file)
{
	authme_err_t res;

	/* Check for necessary info */
	if (in_file == NULL || out_file == NULL)
	{
		fprintf(stderr, "Input and output filenames must be defined\n");
		return -1;
	}

	/* Can we load the service key with what we have? */
	if (authme_load_master_password(psc, password) != AUTHME_ERR_OK)
	{
		fprintf(stderr, "Error loading keyfile\n");
		return -3;
	}



	if (psc->psc_url == NULL)
	{
		fprintf(stderr, "Service URL required for adding secrets\n");
		return -1;
	}

	if (psc->psc_user_id == NULL)
	{
		fprintf(stderr, "User ID must be defined");
		return -1;
	}

	res = authme_decrypt_file(psc, in_file, out_file);

	if (res != AUTHME_ERR_OK)
	{
		fprintf(stderr, "Error: %s\n", psc->psc_last_error);
		return -2;
	}

	fprintf(stderr, "Decrypt done\n");

	return 0;
}

/* ---------------------------------------------------------------- *
 * Ping
 * ---------------------------------------------------------------- */

int
do_ping(authme_service_config_t * psc)
{
	authme_err_t res;

    /* Check for necessary info */
    if (psc->psc_url == NULL)
    {
        fprintf(stderr, "ping command requires URL\n");
        return -1;
    }

    /* Ping the service - get a status message and return */

    res = authme_get_svc_info(psc);

    if (res == AUTHME_ERR_OK)
    {
        printf("Ping succeeded.  Service returned: %s\n", 
               psc->psc_last_error);
        return 0;
    }
    else
        printf("Error: %s\n", psc->psc_last_error);

    return -2;
}

/* ---------------------------------------------------------------- *
* Gen Key
* ---------------------------------------------------------------- */

int
do_key_gen(authme_service_config_t * psc, char * password, char * out_file)
{
	authme_err_t res;

	/* Ensure we have a key filename */
	if (psc->psc_key_file == NULL && out_file == NULL)
	{
		fprintf(stderr, "Key generation requires the key filename (-k) or output filename (--out) be defined\n");
		return -1;
	}

    if (psc->psc_key_file != NULL && out_file != NULL)
    {
        fprintf(stderr, "Key file and output file defined - defaulting to output file\n");
        free(psc->psc_key_file);
        psc->psc_key_file = strdup(out_file);
    }

    else if (psc->psc_key_file == NULL)
    {
        psc->psc_key_file = strdup(out_file);
    }   

	res = authme_generate_master_password(psc, password);

	if (res != AUTHME_ERR_OK)
	{
		printf("Error generating key: %s\n", psc->psc_last_error);
		return -2;
	}

	printf("Key generated in %s\n", psc->psc_key_file);
	return 0;
}

/* ---------------------------------------------------------------- *
 * Main
 * ---------------------------------------------------------------- */

int 
main (int argc, char **argv)
{

	int p, res;
	int do_print_secret = 0;
	char local_key = 0;
	char * in_file = NULL;
	char * out_file = NULL;
	char * key_file_password = NULL;

#if defined (_DEBUG) && defined (_MSC_VER)

	// Do some memory debugging under Visual C++

	_CrtMemState s1, s2, s3;

	// At this point we are about to start really using XSEC, so
	// Take a "before" checkpoing

	_CrtMemCheckpoint(&s1);

#endif

    authme_service_config_t * psc;
    enum {PING,CHECK,STATUS,ADDSECRET,LSAINIT,ENCRYPT,DECRYPT,KEYGEN} command;

	/* init the service library */
	authme_service_init();

    /* Init the configs */
    psc = authme_service_config_create();

    /* Parse the arguments */
    if (argc < 2)
    {
        printUsage(argv[0]);
		authme_service_shutdown();
        return -1;
    }
    
    /* First the command */
    if (strcasecmp(argv[1], "ping") == 0)
        command = PING;
    else if (strcasecmp(argv[1], "check") == 0)
        command = CHECK;
    else if (strcasecmp(argv[1], "status") == 0)
        command = STATUS;
	else if (strcasecmp(argv[1], "addsecret") == 0)
		command = ADDSECRET;
	else if (strcasecmp(argv[1], "encrypt") == 0)
		command = ENCRYPT;
	else if (strcasecmp(argv[1], "decrypt") == 0)
		command = DECRYPT;
	else if (strcasecmp(argv[1], "keygen") == 0)
		command = KEYGEN;
#if defined WIN32
	else if (strcasecmp(argv[1], "lsa-init") == 0)
		command = LSAINIT;
#endif
    else if (strcasecmp(argv[1], "version") == 0)
    {
        printf("AuthMe version %s\n", AUTHME_LIBRARY_VERSION);
        printf("Copyright Berin Lautenbach\n");
        return 0;
    }
	else
    {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        printUsage(argv[0]);
		authme_service_shutdown();
		return -1;
    }

    /* We do two passes through the config arguments.
     * The first is to look for config files.  Then 
     * the rest.  This ensures anything additional overwrites
     * anything loaded from config files
    */

    p = 2;
    int conf_found = 0;
    while (p < argc) {
        if (strcasecmp(argv[p], "--config-file") == 0 ||
            strcasecmp(argv[p], "-f") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "filename required\n");
                printUsage(argv[0]);
                return 0;
            }

            FILE * in = fopen(argv[p], "rt");
            if (in == NULL)
            {
                fprintf(stderr, "Unable to open: ");
                fprintf(stderr, argv[p]);
                fprintf(stderr, "\n");
                return -1;
            }

            if (authme_load_cnf(psc, in, 0) != AUTHME_ERR_OK)
            {
                fprintf(stderr, "Error in config file ");
                if (psc->psc_last_error != NULL)
                    fprintf(stderr, psc->psc_last_error);
                fprintf(stderr, "\n");
                fclose(in);
                return -1;
            }

            fclose(in);
            p++;
            conf_found = 1;
        }
		else
		{
			p++;
		}
    }

    if (!conf_found)
    {
        authme_load_system_cnf(psc, 0);
        authme_load_user_cnf(psc, 0);
    }
    
    p = 2;

    /* Now the arguments */
    while (p < argc) {

        if (strcasecmp(argv[p], "--help") == 0 ||
            strcasecmp(argv[p], "-h") == 0) 
        {

            printUsage(argv[0]);
            return 0;
        }
        else if (strcasecmp(argv[p], "--config-file") == 0 ||
            strcasecmp(argv[p], "-f") == 0) 
        {
            // Already handled - so just skip over
            p += 2;
        }

#if defined WIN32
		else if (strcasecmp(argv[p], "--lsa-key") == 0 ||
			strcasecmp(argv[p], "-l") == 0)
		{
			if (authme_w32_load_master_password(psc) != AUTHME_ERR_OK)
			{
				fprintf(stderr, "Error loading LSA keystore: %s\n", psc->psc_last_error);
				return 0;
			}
			fprintf(stderr, "Keystore loaded\n");
			p++;
		}

#endif

        else if (strcasecmp(argv[p], "--service-url") == 0 ||
            strcasecmp(argv[p], "-r") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "URL required\n");
                printUsage(argv[0]);
                return 0;
            }

            if (psc->psc_url != NULL)
                free(psc->psc_url);

            psc->psc_url = strdup(argv[p++]);

        }

        else if (strcasecmp(argv[p], "--message") == 0 ||
            strcasecmp(argv[p], "-m") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "Message text required\n");
                printUsage(argv[0]);
                return 0;
            }

            if (psc->psc_server_string != NULL)
                free(psc->psc_server_string);

            psc->psc_server_string = strdup(argv[p++]);

        }

		else if (strcasecmp(argv[p], "--password") == 0)
		{

			if (++p == argc) {
				fprintf(stderr, "Password required\n");
				printUsage(argv[0]);
				return 0;
			}

			key_file_password = argv[p++];

		}
		else if (strcasecmp(argv[p], "--userid") == 0 ||
            strcasecmp(argv[p], "-u") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "User ID required\n");
                printUsage(argv[0]);
                return 0;
            }

            if (psc->psc_user_id != NULL)
                free(psc->psc_user_id);

            psc->psc_user_id = strdup(argv[p++]);

        }

        else if (strcasecmp(argv[p], "--checkid") == 0 ||
                 strcasecmp(argv[p], "-c") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "Check ID required\n");
                printUsage(argv[0]);
                return 0;
            }

            if (psc->psc_check_id != NULL)
                free(psc->psc_check_id);

            psc->psc_check_id = strdup(argv[p++]);

        }

		else if (strcasecmp(argv[p], "--secret-id") == 0 ||
			strcasecmp(argv[p], "-i") == 0)
		{

			if (++p == argc) {
				fprintf(stderr, "Secret ID required\n");
				printUsage(argv[0]);
				return 0;
			}

			if (psc->psc_secret_id != NULL)
				free(psc->psc_secret_id);

			psc->psc_secret_id = strdup(argv[p++]);

		}


        else if (strcasecmp(argv[p], "--serverid") == 0 ||
            strcasecmp(argv[p], "-s") == 0) 
        {

            if (++p == argc) {
                fprintf(stderr, "Server ID required\n");
                printUsage(argv[0]);
                return 0;
            }

            if (psc->psc_server_id != NULL)
                free(psc->psc_server_id);

            psc->psc_server_id = strdup(argv[p++]);

        }

		else if (strcasecmp(argv[p], "--print-secret") == 0 ||
			strcasecmp(argv[p], "-p") == 0)
		{
			++p;
			do_print_secret = 1;
		}


		else if (strcasecmp(argv[p], "--key") == 0 ||
			strcasecmp(argv[p], "-k") == 0)
		{

			if (++p == argc) {
				fprintf(stderr, "Key filename required\n");
				printUsage(argv[0]);
				return 0;
			}

			psc->psc_key_file = strdup(argv[p++]);

		}

		else if (strcasecmp(argv[p], "--in") == 0)
		{

			if (++p == argc) {
				fprintf(stderr, "Input filename required\n");
				printUsage(argv[0]);
				return 0;
			}

			in_file = argv[p++];

		}
		
		else if (strcasecmp(argv[p], "--out") == 0)
		{

			if (++p == argc) {
				fprintf(stderr, "Output filename required\n");
				printUsage(argv[0]);
				return 0;
			}

			out_file = argv[p++];

		}

		else if (strcasecmp(argv[p], "--localkey") == 0)
		{
			p++;
			local_key = 1;
		}

		else
        {
            /* Unknown parameter */
            fprintf(stderr, "Unknown argument: %s\n", argv[p]);
            printUsage(argv[0]);
            return -1;
        }
    }

    /* Now action according to the command */

    switch (command)
    {
    case (PING):
        res = do_ping(psc);
        break;
    case (CHECK):
        res = do_check(psc);
        break;
    case (STATUS):
		res = do_status(psc, do_print_secret);
        break;
	case (ADDSECRET) :
		res = do_add_secret(psc);
		break;
	case (ENCRYPT) :
		res = do_encrypt(psc, in_file, out_file, key_file_password, local_key);
		break;
	case (DECRYPT) :
		res = do_decrypt(psc, in_file, key_file_password, out_file);
		break;
	case (KEYGEN) :
		res = do_key_gen(psc, key_file_password, out_file);
		break;
#if defined WIN32
	case (LSAINIT) :
		res = do_lsa_init(psc);
		break;
#endif
    default:
        break;
    }

    /* Free the config structure */
    authme_service_config_free(psc);
	authme_service_shutdown();

#if defined (_DEBUG) && defined (_MSC_VER)

	_CrtMemCheckpoint(&s2);

	if (_CrtMemDifference(&s3, &s1, &s2) && (
		s3.lCounts[0] > 0 ||
		s3.lCounts[1] > 1 ||
		// s3.lCounts[2] > 2 ||  We don't worry about C Runtime
		s3.lCounts[3] > 0 ||
		s3.lCounts[4] > 0)) {

		// Note that there is generally 1 Normal and 1 CRT block
		// still taken.  1 is from Xalan and 1 from stdio

		// Send all reports to STDOUT
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
		_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
		_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
		_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);

		// Dumpy memory stats

		_CrtMemDumpAllObjectsSince(&s3);
		_CrtMemDumpStatistics(&s3);
	}

	// Now turn off memory leak checking and end as there are some 
	// Globals that are allocated that get seen as leaks (Xalan?)

	int dbgFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	dbgFlag &= ~(_CRTDBG_LEAK_CHECK_DF);
	_CrtSetDbgFlag(dbgFlag);

#endif

    return res;

}


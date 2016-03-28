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

//
//  PKCS5PBBKDF2.h
//  AuthMe
//
//  Implements the PKCS5 key derivation algorithm to derive
//  a key from a user's password
//
//  Created by Berin Lautenbach on 16/03/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

@interface PKCS5PBBKDF2 : NSObject {
	
	unsigned long loopCount;
	unsigned char * password;
	int passwordLength;
	unsigned char * salt;
	int saltLength;
	unsigned int iter;
	unsigned char currentBuffer[CC_SHA1_DIGEST_LENGTH];
	int currentBufferPtr;

}

// Sets a new password and resets the internal iteration counts
// pasword is the string to use.  passlen is the number of bytes to take from the string

- (void) setPassword: (NSString *) newPassword
			ofLength: (int) passlen;

// Set the new SALT values
- (void) setSalt: (NSData *) newSalt
			ofLength: (int) saltlen;


// How many rounds do we do?  Be default it's 1000

- (void) setRounds: (unsigned int) newRounds;

// Get a number of bytes from the derivation algorithm

- (BOOL) getBytes: (unsigned char *) outBuffer
		 numBytes: (int) bytes;

@end

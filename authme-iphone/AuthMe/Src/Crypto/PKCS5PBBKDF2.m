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
//  PKCS5PBBKDF2.m
//
//  Created by Berin Lautenbach on 16/03/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "PKCS5PBBKDF2.h"


@implementation PKCS5PBBKDF2

// Initialise
- (id) init
{
	if ((self = [super init]) != nil) {
		
		loopCount = 0;
		password = NULL;
		passwordLength = -1;
		salt = NULL;
		saltLength = 0;
		iter = 1000;   // By default we run 1000 iterations of SHA1 every round
		memset(currentBuffer, 0, CC_SHA1_DIGEST_LENGTH);
		currentBufferPtr = 0;
		
	}
	
	return (self);
	
}

// Perform an iteration of the derivation function
- (void) doRound
{
	
	unsigned char digtmp[CC_SHA1_DIGEST_LENGTH], itmp[4];
	int j, k;
	CCHmacContext hctx;

	
	itmp[0] = (unsigned char)((loopCount >> 24) & 0xff);
	itmp[1] = (unsigned char)((loopCount >> 16) & 0xff);
	itmp[2] = (unsigned char)((loopCount >> 8) & 0xff);
	itmp[3] = (unsigned char)(loopCount & 0xff);

	CCHmacInit(&hctx, kCCHmacAlgSHA1, password, passwordLength);
	CCHmacUpdate(&hctx, salt, saltLength);
	CCHmacUpdate(&hctx, itmp, 4);
	CCHmacFinal(&hctx, digtmp);
	
	memcpy(currentBuffer, digtmp, CC_SHA1_DIGEST_LENGTH);
	
	for(j = 1; j < iter; j++) {
		CCHmac(kCCHmacAlgSHA1, password, passwordLength, digtmp, CC_SHA1_DIGEST_LENGTH, digtmp);
		for(k = 0; k <CC_SHA1_DIGEST_LENGTH; k++) 
			currentBuffer[k] ^= digtmp[k];
	}
	loopCount++;
	currentBufferPtr = 0;  // Not used any of this buffer yet!
	
}

// Set a new password in the object

- (void) setPassword: (NSString *) newPassword
		ofLength: (int) passlen
{
	
	// First clean anything old
	if (password != NULL) {
		free(password);
		password = NULL;
	}
		
	// Is there actually a password?
	if (newPassword == NULL)
	{
		passwordLength = 0;
		return;
	}
	
	// There is - is it a reasonable length?
	if (passlen <= 0)
	{
		passwordLength = (int) [newPassword length];
	} else {
		passwordLength = passlen;
	}

	// Copy it in and lets go!
	password = (unsigned char *) malloc(passlen);
	memcpy(password, [newPassword UTF8String], passwordLength);
	loopCount = 1;
	
	// Trick counter into bypassing first round of copy
	currentBufferPtr = CC_SHA1_DIGEST_LENGTH;
	
}

// Set the new SALT values
- (void) setSalt: (const NSData *) newSalt
		ofLength: (int) saltlen
{
	
	if (salt != NULL) {
		free(salt);
		salt = NULL;
	}
	
	saltLength = saltlen;
	if (saltLength > 0) {
		salt = (unsigned char *) malloc(saltlen);
		memcpy(salt, [newSalt bytes], saltlen);
	}
	
	// Trick counter into bypassing first round of copy
	currentBufferPtr = CC_SHA1_DIGEST_LENGTH;

}

// How many rounds do we do?  Be default it's 1000

- (void) setRounds: (unsigned int) newRounds
{
	iter = newRounds;
	
}



// Get some derived key bytes!

- (BOOL) getBytes: (unsigned char *) outBuffer
		 numBytes: (int) bytes
{
	int bytesToGo = bytes;
	int i = 0;
	int cpLen;
	
	while (i < bytes) {
		
		if ((CC_SHA1_DIGEST_LENGTH - currentBufferPtr) < bytesToGo)
			cpLen = CC_SHA1_DIGEST_LENGTH - currentBufferPtr;
		else 
			cpLen = bytesToGo;
		
		memcpy(&outBuffer[i], &currentBuffer[currentBufferPtr], cpLen);
		
		i += cpLen;
		bytesToGo -= cpLen;
		currentBufferPtr += cpLen;
		
		// Do we do another round?
		if (currentBufferPtr == CC_SHA1_DIGEST_LENGTH)
			[self doRound];
		
	}
	
	return TRUE;
}

@end

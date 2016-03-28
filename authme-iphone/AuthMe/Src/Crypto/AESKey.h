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
//  AESKey.h
//  AuthMe
//
//  Created by Berin Lautenbach on 9/08/10.
//  Copyright 2010 Wings of Hermes. All rights reserved.
//

#import <Foundation/Foundation.h>

#define _AUTHME_ENCRYPT_BLOCK_SIZE		16				/* Block size in bytes */
#define _AUTHME_ENCRYPT_KEY_LENGTH		32				/* Key size in bytes */

/* Base class to implement the AuthMe version of AES */

@interface AESKey : NSObject {

	/* key to use for encryption */
	unsigned char * key;

}

@property unsigned char * key;

/**
 * 
 * This function is a self contained encrypt function.  It generates an IV, does the encrypt,
 * prepends the IV to the data and then base64 encodes the result.
 *
 * Note that AuthMe only uses base64 encrypted blocks.  It never deals in "binary" encrypted data
 * other than directly inside these function.
 */

// Use key to encrypt a block of data into a Base64 NSString
- (NSString *) encrypt: (NSData *) plain plainLength: (size_t) plainLength;
- (NSString *) encrypt: (NSString *) plain;

/**
 * Decrypt data 
 *
 * Input data is expected to be in a Base64 format string with the first _AUTHME_ENCRYPT_BLOCKSIZE
 * worth of data being an IV
 */

- (NSMutableData *) decrypt: (NSString *) cipher cipherLength: (size_t) cipherLength;
- (NSMutableData *) decryptData: (NSData *) cipher;

/**
 * Generate a random key
 *
 * For cases where we want to create a new key from scratch
 */

- (BOOL) generateKey;

/**
 * Load a key from an NSData
 */

- (BOOL) loadKey: (NSData *) inData;

/**
 * get Key
 *
 * Returns the key as a NSData 
 */

- (NSData *) getKeyAsData;

/**
 * get KCV
 *
 * Returns the Key Check Value for this key
 */

- (NSString *) getKCV;

/**
 * check KCV
 *
 * param kcv is the base64 encoded Key CHeck value to check against
 */

- (BOOL) checkKCV: (NSString *) kcv;

/**
 * setKeyFromPassword
 *
 * Generates a key from a password
 */

- (void) setKeyFromPassword: (NSString *) pw 
                   withSalt: (NSData *) salt
                   ofLength: (unsigned int) saltLength;


@end

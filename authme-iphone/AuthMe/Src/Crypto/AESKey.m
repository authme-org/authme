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
//  AESKey.m
//  AuthMe
//
//  Created by Berin Lautenbach on 9/08/10.
//  Copyright 2010 Wings of Hermes. All rights reserved.
//

#import "AESKey.h"
#import "Base64.h"
#import "PKCS5PBBKDF2.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>


@implementation AESKey

@synthesize key;

#pragma mark -
#pragma mark Admin

- (id) init {
	
	if ((self = [super init]) != nil) {
		/* Allocate and clear the key */
		key = (unsigned char *) malloc(_AUTHME_ENCRYPT_KEY_LENGTH);
		memset(key, 0, _AUTHME_ENCRYPT_KEY_LENGTH);
	}
	
	return (self);
}

#pragma mark -
#pragma mark Key Handling

/* Generate a random key */
- (BOOL) generateKey {
	
	if (SecRandomCopyBytes(kSecRandomDefault, _AUTHME_ENCRYPT_KEY_LENGTH, key) != 0) {
		NSLog(@"Error generating AES Key value");
		/* Should be more graceful */
		return FALSE;
	}	
	
	return TRUE;
}
	
- (NSString *) getKCV {
	
	/* KCV is the first 8 bytes of a SHA-256 hash of the unencrypted key.  It is always Base64 encoded
	 * for all web service calls
	 */
	
	unsigned char hashedChars[32];
	CC_SHA256(key, _AUTHME_ENCRYPT_KEY_LENGTH, hashedChars);
	
	/* Now base64 encode */
	Base64 * base64 = [[Base64 alloc] init];
    NSData * hashData = [[NSData alloc] initWithBytes:hashedChars length:8];
	NSString * ret = [base64 base64encode:hashData length:8];
	
	return ret;
	
}

- (NSData *) getKeyAsData {
    
    if (key == NULL)
        return NULL;
    
    return [[NSData alloc] initWithBytes: key length: _AUTHME_ENCRYPT_KEY_LENGTH];
    
}


- (BOOL) checkKCV: (NSString *) kcv {

	/* first decode the input string and make sure it makes sense */
	Base64 * base64 = [[Base64 alloc] init];
	NSData * input = [base64 base64decode:kcv length:(int)[kcv length]];

	if ([input length] != 8)
		return FALSE;
	
	/* OK - now compare to the one we get from our own key */
	unsigned char hashedChars[32];
	CC_SHA256(key, _AUTHME_ENCRYPT_KEY_LENGTH, hashedChars);

	unsigned char * inChar = (unsigned char *) [input bytes];
	for (int i = 0; i < 8; ++i)
		if (inChar[i] != hashedChars[i])
			return FALSE;
	
	return TRUE;
}

- (void) setKeyFromPassword: (NSString *) pw 
                   withSalt: (NSData *) salt
                   ofLength: (unsigned int) saltLength {
    
    // Nope - use PKCS 5 to generate the required data
    PKCS5PBBKDF2 * pk = [[PKCS5PBBKDF2 alloc] init];

    [pk setSalt: salt ofLength: saltLength];
    [pk setPassword:pw ofLength:(int) [pw length]];
    [pk setRounds: 100];

    // setup done - generate the wrapper key
    if (key != nil)
        free(key);
    
    key = (unsigned char *) malloc(_AUTHME_ENCRYPT_KEY_LENGTH);
    [pk getBytes:key numBytes:_AUTHME_ENCRYPT_KEY_LENGTH];

}

- (BOOL) loadKey: (NSData *) inData {
    
    if ([inData length] != _AUTHME_ENCRYPT_KEY_LENGTH) {
        return NO;
    }
    
    if (key != nil)
        free(key);
    
    key = (unsigned char *) malloc(_AUTHME_ENCRYPT_KEY_LENGTH);
    memcpy(key, [inData bytes], _AUTHME_ENCRYPT_KEY_LENGTH);
    
    return YES;
}


#pragma mark -
#pragma mark Encryption operations

/**
 * 
 * This function is a self contained encrypt function.  It generates an IV, does the encrypt,
 * prepends the IV to the data and then base64 encodes the result.
 * Note that AuthMe only uses base64 encrypted blocks.  It never deals in "binary" encrypted data
 * other than directly inside these function.
 */

// Use master password to encrypt a block of data into a Base64 NSString
- (NSString *) encrypt: (NSData *) plain plainLength: (size_t) plainLength {
	
	// Create a temporary output block 
	size_t tmpOutputLength = plainLength + (2 * _AUTHME_ENCRYPT_BLOCK_SIZE);
	unsigned char * tmpEncrypt = 
	(unsigned char *) malloc(tmpOutputLength);
	
	// Create a new IV - every new encrypt uses a new IV
	if (SecRandomCopyBytes(kSecRandomDefault, _AUTHME_ENCRYPT_BLOCK_SIZE, tmpEncrypt) != 0) {
		NSLog(@"Error generating IV value");
		/* Should be more graceful */
		free(tmpEncrypt);
		abort();
	}	
	
	// Use Common Crypto to do encrypt (Appears to be a wrapper around OpenSSL?)
	
	size_t encryptedLength = 0;
	int status = 
	CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, key, _AUTHME_ENCRYPT_KEY_LENGTH,
			tmpEncrypt, plain.bytes, plainLength, &tmpEncrypt[_AUTHME_ENCRYPT_BLOCK_SIZE], tmpOutputLength - _AUTHME_ENCRYPT_BLOCK_SIZE,
			&encryptedLength);
	
	if (status != kCCSuccess) {
		NSLog(@"MasterPassword:Encrypt - Error Creating Cryptor");
		free(tmpEncrypt);
		return NULL;
	}
	
	// Cater for IV
	encryptedLength += _AUTHME_ENCRYPT_BLOCK_SIZE;
	
	// Now bundle into a Base64 string
	Base64 *base64 = [[Base64 alloc] init];
    NSData * tmpData = [[NSData alloc] initWithBytes:tmpEncrypt length:encryptedLength];
	NSString *encodedCheckValue = [base64 base64encode:tmpData
												length:(int)encryptedLength];
	
	free(tmpEncrypt);
	return encodedCheckValue;
}

- (NSString *) encrypt:(NSString *)plain {
    
    // Lazy but easy
    NSData * toEncrypt = [plain dataUsingEncoding:NSUTF8StringEncoding];
    return [self encrypt:toEncrypt plainLength:[toEncrypt length]];
    
}

/**
 * Decrypt data using the master password.
 *
 * Input data is expected to be in a Base64 format string with the first _AUTHME_ENCRYPT_BLOCKSIZE
 * worth of data being an IV
 */

- (NSMutableData *) decryptData: (NSData *) cipher {
		
	// Get buffer and encrypted data length
	unsigned char * cipherData = (unsigned char *)[cipher bytes];
	size_t cipherDataLength = [cipher length];
	
	// Create a plain text buffer
	unsigned char * plainText;
	size_t plainTextLength;
    
	if (cipherDataLength < _AUTHME_ENCRYPT_BLOCK_SIZE) {
		NSLog(@"Error decrypting data - cipher data length too small");
		return NULL;
	}
	
	cipherDataLength -= _AUTHME_ENCRYPT_BLOCK_SIZE;
	
	plainText = (unsigned char *) malloc(cipherDataLength);
	
	// Common Crypto to the rescue
	int status =
	CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, key, _AUTHME_ENCRYPT_KEY_LENGTH,
			cipherData, &cipherData[_AUTHME_ENCRYPT_BLOCK_SIZE], cipherDataLength, 
			plainText, cipherDataLength, &plainTextLength);
	
	if (status != kCCSuccess) {
		NSLog(@"MasterPassword:Decrypt - Error in decrypt operation");
		free(plainText);
		return NULL;
	}
	
	// Load into an NSMutableData
	NSMutableData * ret = [NSMutableData dataWithBytes: plainText length: plainTextLength];
	free (plainText);
	
	return ret;
}

- (NSMutableData *) decrypt: (NSString *) cipher cipherLength: (size_t) cipherLength {
    
    // Clean up default length
    if (cipherLength == 0) {
        cipherLength = [cipher length];
    }
    
    // Decode the Base64 data
    Base64 * base64 = [[Base64 alloc] init];
    NSMutableData *cipherMutableData =
    [base64 base64decode:cipher length:(int)cipherLength];
    
    return [self decryptData:cipherMutableData];
}

@end

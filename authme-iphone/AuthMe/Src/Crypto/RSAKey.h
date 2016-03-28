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
//  RSAKey.h
//  AuthMe
//
//  Created by Berin Lautenbach on 18/01/2014.
//  Copyright (c) 2014 Berin Lautenbach. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAKey : NSObject {
    
    SecKeyRef publicKeyRef;
    SecKeyRef privateKeyRef;
    
    NSString * publicKeyIdentifier;
    NSString * privateKeyIdentifier;
    
    NSData * kcv;
    
    int keyLength;

}

- (id) initWithIdentifier: (NSString *) ident;


/**
 *
 * This function is a self contained encrypt function.  It performs an RSA
 * encrypt and base64 encodes the results
 *
 * Note that AuthMe only uses base64 encrypted blocks.  It never deals in "binary" encrypted data
 * other than directly inside these function.
 */

- (NSString *) encrypt: (NSData *) plain plainLength: (size_t) plainLength;

/**
 * Decrypt data
 *
 * Input data is expected to be in a Base64 or NSData (raw bytes) format - default is to use
 * private key
 */

- (NSData *) decrypt: (NSString *) cipher;
- (NSData *) decrypt: (NSString *) cipher usePublicKey: (BOOL) usePublicKey;
- (NSData *) decryptData: (NSData *) cipher usePublicKey: (BOOL) usePublicKey;
- (NSData *) decryptData: (NSData *) cipher;

/**
 * Sign a document
 *
 * Generates the Base64 signature
 */

- (NSString *) sign: (NSData *) input;

/**
 * Check signature
 *
 * Input data is expected to be in a Base64 format
 * Returns TRUE if signature validated.  FALSE otherwise
 */

- (BOOL) checkSig: (NSString *) signature input: (NSData *) input;


/**
 * Generate a random key
 *
 * For cases where we want to create a new key from scratch
 */

- (BOOL) generateKey: (int) numBits;


/**
 * get Key Length
 *
 * When the public key is loaded, the key length is also loaded.
 *
 * NOTE: Get keys in bytes - multiply by 8 to get bit length
 */

- (int) getKeyLength;


/**
 * Manage the key pair - all input and output is done in Base64 and expected
 * to be in PKCS1 format
 *
 * NOTE: we load public/private keys separately as sometimes you only have a
 * public key for signature verification or encrypting
 */

- (BOOL) loadPublicKey: (NSString *) publicKey;
- (BOOL) loadPrivateKey: (NSString *) privateKey;
- (BOOL) loadRawPrivateKey: (NSData *) rawFormattedKey;
- (BOOL) loadPKCS8PrivateKey: (NSData *) privateKey;
- (BOOL) loadKeysFromKeychain;

- (NSString *) getPublicKey;
- (NSString *) getPrivateKey;
- (NSString *) getPKCS8PrivateKey;

- (BOOL) destroyKey: (BOOL) removeFromKeyChain;

- (void) calculateKCV: (NSData *) privateKeyBytes;
- (BOOL) compareKCV: (NSString *) kcvString;
- (NSString *) getKCV;

@end

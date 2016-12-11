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
//  RSAKey.m
//  AuthMe
//
//  Created by Berin Lautenbach on 18/01/2014.
//  Copyright (c) 2014 Berin Lautenbach. All rights reserved.
//

#import "RSAKey.h"
#import "Base64.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>


@implementation RSAKey

static const unsigned char _encodedRSAEncryptionOID[15] = {
    
    /* Sequence of length 0xd made up of OID followed by NULL */
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    
};

static const unsigned char _encodedRSAPrivateKeyVersion[3] = {
    0x02, 0x01, 0x00
};

#pragma mark -
#pragma mark Initialisation

size_t getEncodeLengthASNLength(size_t length) {
    
    size_t i = 0;
    while (length > 0) {
        length = length >> 8;
        ++i;
    }
    
    return i;
    
}

size_t encodeLengthASN(unsigned char * buf, size_t length) {
	
	// encode length in ASN.1 DER format
	if (length < 128) {
		buf[0] = length;
		return 1;
	}
    
    getEncodeLengthASNLength(length);
	
    size_t i = getEncodeLengthASNLength(length);
	buf[0] = i + 0x80;
	for (size_t j = 0 ; j < i; ++j) {
		buf[i - j] = length & 0xFF;
		length = length >> 8;
	}
	
	return i + 1;
}

#pragma mark -
#pragma mark Initialisation

- (id) initWithIdentifier: (NSString *) ident {
	
	if ((self = [super init]) != nil) {
        
		/* Allocate and clear the key */
        publicKeyIdentifier = [[NSString alloc] initWithFormat:@"%@.%@", ident, @".public"];
        privateKeyIdentifier = [[NSString alloc] initWithFormat:@"%@.%@", ident, @".private"];
        
        publicKeyRef = nil;
        privateKeyRef = nil;
        
        keyLength = 0;
        
        kcv = nil;
        
	}
	
	return (self);
}

- (id) init {
    
    return [self initWithIdentifier:@"org.authme.defaultId"];
}

#pragma mark -
#pragma mark Key Generation

- (BOOL) generateKey: (int) numBits {
    
    // Generate the basic parameter setup
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
	NSData * publicTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
	NSData * privateTag = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
	
	
	// Public key attributes
	[publicKeyAttr setObject:[NSNumber numberWithBool:NO]
					  forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag
					  forKey:(__bridge id)kSecAttrApplicationTag];
    
	// Private key attributes
	[privateKeyAttr setObject:[NSNumber numberWithBool:NO]
					   forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag
					   forKey:(__bridge id)kSecAttrApplicationTag];
	
	// General key attributes
	[keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:numBits] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
	// Link the public/private key attributes in
	[keyPairAttr setObject:(id)publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
	[keyPairAttr setObject:(id)privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    
	// Generate keys
	OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef) keyPairAttr, &publicKeyRef, &privateKeyRef );
	
	if ( status != 0 ) {
		NSLog( @"SecKeyGeneratePair failed" );
		publicKeyRef = nil;
		privateKeyRef = nil;
		
		return NO;
	}
    keyLength = numBits / 8;
    
	return YES;

}

#pragma mark -
#pragma mark Key Load/Unload

- (void) calculateKCV: (NSData *) privateKeyBytes {
    
    /* OK - now compare to the one we get from our own key */
    unsigned char hashedChars[32];
    CC_SHA256((unsigned char * ) [privateKeyBytes bytes], (unsigned int)[privateKeyBytes length], hashedChars);
    
    kcv = [[NSData alloc] initWithBytes:hashedChars length:8];
    
}

- (BOOL) checkKCV: (NSData *) privateKeyBytes {
    
    if ([privateKeyBytes length] != 256 || kcv == nil)
        return FALSE;
    
    /* OK - now compare to the one we get from our own key */
    unsigned char hashedChars[32];
    CC_SHA256((unsigned char * ) [privateKeyBytes bytes], 256, hashedChars);
    
    unsigned char * inChar = (unsigned char *) [kcv bytes];
    for (int i = 0; i < 8; ++i)
        if (inChar[i] != hashedChars[i])
            return FALSE;
    
    return TRUE;

}

- (BOOL) compareKCV: (NSString *) kcvString {
    
    Base64 * b64 = [[Base64 alloc] init];
    NSData * inKcv = [b64 base64decode:kcvString length:(int)[kcvString length]];
    
    return [inKcv isEqualToData:kcv];
}

- (NSString *) getKCV {
    
    Base64 * base64 = [[Base64 alloc] init];
    NSString * ret = [base64 base64encode:kcv length:8];
    
    return ret;

}

- (BOOL) loadPublicKey: (NSString *) publicKey {
    
    if (publicKeyRef != nil) {
        CFRelease(publicKeyRef);
        publicKeyRef = nil;
    }
    
    /* First decode the Base64 string */
    Base64 * b64 = [[Base64 alloc] init];
    NSData * rawFormattedKey = [b64 base64decode:publicKey length:(int) [publicKey length]];
    
    /* Now strip the uncessary ASN encoding guff at the start */
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    /* Strip the initial stuff */
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return FALSE;
    
    /* Skip size bytes */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i] != 0x30)
        return FALSE;
    
    /* Skip OID */
    i += 15;
    
    if (i >= bytesLen - 2)
        return FALSE;
    
    if (bytes[i++] != 0x03)
        return FALSE;
    
    /* Skip length and null */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i++] != 0x00)
        return FALSE;
    
    if (i >= bytesLen)
        return FALSE;
    
    /* Here we go! */
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    /* Should be at start of a sequence */
    if (bytes[i] != 0x30)
        return FALSE;
    
    /* Get the size of the key */
    size_t j = i+1;
    if (bytes[j] <= 0x80)
        j++;
    else
        j += bytes[j] - 0x80 +1;
    
    j++;
    
    // We are now at the modulus
    if (bytes[j] <=0x80)
        keyLength = bytes[j];
    else {
        size_t k = bytes[j++] - 0x80;
        keyLength = 0;
        while (k > 0) {
            keyLength = (keyLength << 8) | bytes[j];
            ++j;
            --k;
        }
    }
    
    /* Strip leading 0s */
    keyLength = keyLength - (keyLength % 8);
    
    /* Load as a key ref */
    OSStatus error = noErr;
    
    NSData * refTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * keyAttr = [[NSMutableDictionary alloc] init];
    
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    /* First we delete any current keys */
    error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    
    NSMutableDictionary * keyAttrAdd = [keyAttr mutableCopy];
    [keyAttrAdd setObject:extractedKey forKey:(__bridge id)kSecValueData];
    [keyAttrAdd setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    error = SecItemAdd((__bridge CFDictionaryRef) keyAttrAdd, (CFTypeRef *)&publicKeyRef);
    
    if (publicKeyRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Problem adding public key to keychain");
        return FALSE;
    }
    
    error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    if (error != noErr)
        NSLog(@"Error deleting persistent key reference");
    
#if 0
    CFRelease(persistPeer);
    
    /* Now we extract the real ref */
    [keyAttr removeAllObjects];
    /*
     [keyAttr setObject:(id)persistPeer forKey:(id)kSecValuePersistentRef];
     [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
     */
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the persistent key reference.
    error = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&publicKeyRef);
    
    if (publicKeyRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Error retrieving public key reference from chain");
        return FALSE;
    }
#endif
    
    return TRUE;
    
    
    
}

- (BOOL) loadRawPrivateKey: (NSData *) rawFormattedKey {
    
    if (privateKeyRef != nil) {
        CFRelease(privateKeyRef);
        privateKeyRef = nil;
    }
    
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    /* Now we load */
    NSData * extractedKey = [NSData dataWithBytes:bytes length:bytesLen];
    
    /* Load as a key ref */
    OSStatus error = noErr;
    
    NSData * refTag = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * keyAttr = [[NSMutableDictionary alloc] init];
    
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    /* First we delete any current keys */
    error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    
    NSMutableDictionary * keyAttrAdd = [keyAttr mutableCopy];
    [keyAttrAdd setObject:extractedKey forKey:(__bridge id)kSecValueData];
    [keyAttrAdd setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    error = SecItemAdd((__bridge CFDictionaryRef) keyAttrAdd, (CFTypeRef *)&privateKeyRef);
    
    if (privateKeyRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Problem adding private key to keychain");
        return FALSE;
    }
    
    error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    if (error != noErr)
        NSLog(@"Error deleting persistent key reference");
    
#if 0
    
    CFRelease(persistPeer);
    
    /* Now we extract the real ref */
    [keyAttr removeAllObjects];
    /*
     [keyAttr setObject:(id)persistPeer forKey:(id)kSecValuePersistentRef];
     [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
     */
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the persistent key reference.
    error = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&privateKeyRef);
    
    if (privateKeyRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Error retrieving public key reference from chain");
        return FALSE;
    }
#endif
    
    return TRUE;
}

- (BOOL) loadPKCS8PrivateKey: (NSData *) privateKey {
    
    [self calculateKCV:privateKey];
    
    /* Strip the uncessary ASN encoding guff at the start */
    unsigned char * bytes = (unsigned char *)[privateKey bytes];
    size_t bytesLen = [privateKey length];
    
    // Too short?
    if (bytesLen < 100)
        return FALSE;
    
    /* Strip the initial stuff */
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return FALSE;
    
    /* Skip size bytes */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i + 3 >= bytesLen)
        return FALSE;
    
    /* Skip the version bytes */
    if (bytes[i++] != 0x02)
        // INTEGER
        return FALSE;
    
    if (bytes[i++] != 0x01)
        // OF SIZE 1 BYTE
        return FALSE;
    
    if (bytes[i++] != 0x00)
        // VERSION 0
        return FALSE;
    
    if (bytes[i] != 0x30)
        return FALSE;
    
    /* Skip OID */
    i += 15;
    
    if (i >= bytesLen - 2)
        return FALSE;
    
    if (bytes[i++] != 0x04)
        // OCTET-STRING
        return FALSE;
    
    /* Skip length */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    /* Here we go! */
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    /* Should be at start of a sequence */
    if (bytes[i] != 0x30)
        return FALSE;
    
    return [self loadRawPrivateKey:extractedKey];
    
}

- (BOOL) loadPrivateKey: (NSString *) privateKey {
    
    /* First decode the Base64 string */
    Base64 * b64 = [[Base64 alloc] init];
    NSData * rawFormattedKey = [b64 base64decode:privateKey length:(int) [privateKey length]];
    
    return [self loadRawPrivateKey:rawFormattedKey];
    
}

- (BOOL) loadKeysFromKeychain {
    
	// Now lets exract the public key
	NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
	
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:publicKeyIdentifier forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
	[queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
	
	OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyRef);
    
	if (err != noErr || publicKeyRef == nil) {
		publicKeyRef = nil;
        return FALSE;
	}
    
	// Now get a ref to the private key
	[queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPrivateKey setObject:privateKeyIdentifier forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];

	
	err = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyRef);
	
	if (err != noErr || privateKeyRef == nil) {
		privateKeyRef = nil;
        return FALSE;
	}
    
    // Get Key Size
    keyLength = (int) SecKeyGetBlockSize(publicKeyRef);
    
    return TRUE;
}


- (BOOL) destroyKey: (BOOL) removeFromKeyChain {

    if (publicKeyRef != nil) {
        CFRelease(publicKeyRef);
        publicKeyRef = nil;
    }

    if (privateKeyRef != nil) {
        CFRelease(privateKeyRef);
        privateKeyRef = nil;
    }
    
    /* Remove from KeyChain if we need to */
    if (!removeFromKeyChain)
        return TRUE;

    // Private key
    NSData * refTag = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * keyAttr = [[NSMutableDictionary alloc] init];
    
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    if (SecItemDelete((__bridge CFDictionaryRef) keyAttr) != noErr)
        return FALSE;

    // Public key
    refTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    [keyAttr setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    if (SecItemDelete((__bridge CFDictionaryRef) keyAttr) != noErr)
        return FALSE;
    
    return TRUE;
}

#pragma mark -
#pragma mark Get Keys

- (NSString *) getPrivateKey {
	
	// Now lets extract the private key - build query to get bits
    
	NSData * refTag = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
	
	[queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPrivateKey setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
	[queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    NSMutableDictionary * attributes = [queryPrivateKey mutableCopy];
    [attributes setObject:(__bridge id)privateKeyRef forKey:(__bridge id)kSecValueRef];
    [attributes setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
	
    CFTypeRef copyReturn;
    
    // Temporarily add to keychain
    
    OSStatus err = SecItemAdd((__bridge CFDictionaryRef)attributes, &copyReturn);
    
    if (err != noErr) {
        return nil;
    }
    
    NSData * privateKeyBits = (__bridge NSData *) copyReturn;
    err = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    if (err != noErr) {
        return nil;
    }
	// Now translate the result to a Base64 string
	Base64 * base64 = [[Base64 alloc] init];
	NSString * ret = [base64 base64encode:privateKeyBits length:(int)[privateKeyBits length]];
    
    CFRelease(copyReturn);
	
	return ret;

}

- (NSString *) getPKCS8PrivateKey {
    
    // First extract the private key - build query to get bits
    
    NSData * refTag = [privateKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    NSMutableDictionary * attributes = [queryPrivateKey mutableCopy];
    [attributes setObject:(__bridge id)privateKeyRef forKey:(__bridge id)kSecValueRef];
    [attributes setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef copyReturn;
    
    // Temporarily add to keychain
    
    OSStatus err = SecItemAdd((__bridge CFDictionaryRef)attributes, &copyReturn);
    
    if (err != noErr) {
        return nil;
    }
    
    NSData * privateKeyBits = (__bridge NSData *) copyReturn;
    err = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    if (err != noErr) {
        return nil;
    }
    
    /* Encode the Octets into the first data buffer */
    unsigned char builder[15];
    NSMutableData * privateOctets = [[NSMutableData alloc] init];
    int bitstringEncLength;
        
    // Overall we have a sequence of a certain length
    [privateOctets appendBytes:_encodedRSAEncryptionOID length:sizeof(_encodedRSAEncryptionOID)];
    builder[0] = 0x04;  // Octets
    [privateOctets appendBytes:builder length:1];

    // Write out the octet string
    size_t i = [privateKeyBits length];
    size_t j = encodeLengthASN(&builder[0], i);
    [privateOctets appendBytes:builder length:j];
    [privateOctets appendData:privateKeyBits];
    
    /* Now the overall */
    
    NSMutableData * encKey = [[NSMutableData alloc] init];
    
    /* Total length */
    i = sizeof(_encodedRSAPrivateKeyVersion) + [privateOctets length];
    
    // When we get to the bitstring - how will we encode it?
     if (i < 128)
         bitstringEncLength = 1;
     else
         bitstringEncLength = (int) getEncodeLengthASNLength(i + 1) + 1;
     
     // Overall we have a sequence of a certain length
     builder[0] = 0x30;	// ASN.1 encoding representing a SEQUENCE
    
     // Build up overall size made up of - size of OID + size of bitstring encoding + size of actual key
     j = encodeLengthASN(&builder[1], i);
     [encKey appendBytes:builder length:j +1];
    
     // Version bytes
     [encKey appendBytes:_encodedRSAPrivateKeyVersion length: sizeof(_encodedRSAPrivateKeyVersion)];
    
     // Add the earlier wrapped private key
     [encKey appendData:privateOctets];
     
     // Now translate the result to a Base64 string
     Base64 * base64 = [[Base64 alloc] init];
     NSString * ret = [base64 base64encode:encKey length: (int) [encKey length]];
     
     return ret;
 }

- (NSString *) getPublicKey {
    
    NSData * publicTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
	// Now lets extract the public key - build query to get bits
	NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
	
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];

    NSMutableDictionary * attributes = [queryPublicKey mutableCopy];
    [attributes setObject:(__bridge id)publicKeyRef forKey:(__bridge id)kSecValueRef];
    [attributes setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];

    CFTypeRef copyReturn;
    
    // Temporarily add to keychain
    
	OSStatus err = SecItemAdd((__bridge CFDictionaryRef)attributes, &copyReturn);
	
	if (err != noErr) {
		return nil;
	}
    
    NSData * publicKeyBits = (__bridge NSData *) copyReturn;
    err = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
    if (err != noErr) {
        return nil;
    }
	
	// OK - that gives us the "BITSTRING component of a full DER encoded RSA public key - we now need to build the rest
	unsigned char builder[15];
	NSMutableData * encKey = [[NSMutableData alloc] init];
	int bitstringEncLength;
	
	// When we get to the bitstring - how will we encode it?
	if ([publicKeyBits length] + 1 < 128)
		bitstringEncLength = 1;
	else
        bitstringEncLength = (int) getEncodeLengthASNLength([publicKeyBits length] +1) + 1;
	
	// Overall we have a sequence of a certain length
	builder[0] = 0x30;	// ASN.1 encoding representing a SEQUENCE
                        // Build up overall size made up of - size of OID + size of bitstring encoding + size of actual key
	size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength + [publicKeyBits length];
	size_t j = encodeLengthASN(&builder[1], i);
	[encKey appendBytes:builder length:j +1];
    
	// First part of the sequence is the OID
	[encKey appendBytes:_encodedRSAEncryptionOID length:sizeof(_encodedRSAEncryptionOID)];
	
	// Now add the bitstring
	builder[0] = 0x03;
	j = encodeLengthASN(&builder[1], [publicKeyBits length] + 1);
	builder[j+1] = 0x00;
	[encKey appendBytes:builder length:j + 2];
    
	// Now the actual key
	[encKey appendData:publicKeyBits];
#if 0
	unsigned char * pkb = [publicKeyBits bytes];
#endif
	
	// Now translate the result to a Base64 string
	Base64 * base64 = [[Base64 alloc] init];
	NSString * ret = [base64 base64encode:encKey length: (int) [encKey length]];
	
	return ret;

    
}


#pragma mark -
#pragma mark Encryption

- (NSString *) encrypt: (NSData *) plain plainLength: (size_t) plainLength {
	
	if (plainLength >= [self getKeyLength]) {
		NSLog(@"Attempt to encrypt too much data for our key length");
		return nil;
	}
	
    if (publicKeyRef == nil)
        return nil;
    
	/* Do encrypt - actually only need 256 bytes*/
	size_t outputSize = [self getKeyLength];
    unsigned char * output = (unsigned char *) malloc(outputSize + 1);
    
	int status = SecKeyEncrypt(publicKeyRef,
							   kSecPaddingPKCS1,
							   [plain bytes],
							   plainLength,
							   output,
							   &outputSize);
	
	if (status != noErr) {
		NSLog(@"Public key encrypt failed");
		return nil;
	}
	
	NSString * ret;
	Base64 * base64 = [[Base64 alloc] init];
	ret = [base64 base64encode:[[NSData alloc] initWithBytes:output length:outputSize] length:(int) outputSize];
	
	return ret;
	
}

#pragma mark -
#pragma mark Decryption

- (NSData *) decryptData: (NSData *) cipher usePublicKey: (BOOL) usePublicKey {

    SecKeyRef decryptKeyRef = (usePublicKey) ? publicKeyRef : privateKeyRef;
    
    if (decryptKeyRef == nil)
        return nil;
    
    size_t cipherLength = [cipher length];
    
    /* Do decrypt */
    unsigned char * output = (unsigned char *) malloc(cipherLength);
    size_t outputSize = cipherLength;
    
    /* First try the "proper" way */
    int status = SecKeyDecrypt(decryptKeyRef,
                               kSecPaddingPKCS1,
                               [cipher bytes],
                               cipherLength,
                               output,
                               &outputSize);
    
    if (status == noErr) {
        NSData * ret = [[NSData alloc] initWithBytes:output length:outputSize];
        return ret;
    }
    
    /* Note there is some wierd sh*t happening here.  The iPhone
     * library does not properly decode PKCS1 padding so it has to be done
     * manually.  Thus we use a kSecPaddingNone value for padding */
    
    status = SecKeyDecrypt(decryptKeyRef,
                           kSecPaddingNone,
                           [cipher bytes],
                           cipherLength,
                           output,
                           &outputSize);
    
    if (status != noErr) {
        NSLog(@"Decrypt failed");
        return nil;
    }
    
    int i = 0;
    /* Get rid of the PKCS1 padding */
    if (output[0] == 0x0 && output[1] == 0x02) {
        i = 2;
    }
    else if (output[0] == 0x02) {
        // This is really cheating - but happens because the RSA decrypt strips the leading 0
        i = 1;
    }
    else {
        // Padding error
        return nil;
    }
    
    while (i < outputSize && output[i] != 0x00)
        ++i;
    
    ++i;
    
    if (i >= cipherLength)
        return nil;
    
    // The rest of the buffer is our data
    NSData * ret = [[NSData alloc] initWithBytes:&output[i] length:outputSize - i];
    
    return ret;
    
}

- (NSData *) decrypt: (NSString *) cipher usePublicKey: (BOOL) usePublicKey {

    SecKeyRef decryptKeyRef = (usePublicKey) ? publicKeyRef : privateKeyRef;
    
    if (decryptKeyRef == nil)
        return nil;
    
    /* Decode */
    Base64 * base64 = [[Base64 alloc] init];
    NSData * rawCipher = [base64 base64decode:cipher length:(int) [cipher length]];
    
    return [self decryptData:rawCipher usePublicKey:usePublicKey];

}

- (NSData *) decrypt: (NSString *) cipher {
    
    return [self decrypt:cipher usePublicKey:NO];
    
}

- (NSData *) decryptData: (NSData *) cipher {
    
    return [self decryptData:cipher usePublicKey:NO];
    
}

#pragma mark -
#pragma mark Signature Management

- (BOOL) checkSig: (NSString *) signature input: (NSData *) input {
    
    if (publicKeyRef == nil)
        return FALSE;
    
    /* Decode */
    Base64 * base64 = [[Base64 alloc] init];
    NSData * rawCipher = [base64 base64decode:signature length:(int)[signature length]];
    
    /* Now hash */
    unsigned char digtmp[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1([input bytes], (CC_LONG) [input length], digtmp);

    OSStatus status = SecKeyRawVerify(publicKeyRef, kSecPaddingPKCS1SHA1,
                    digtmp,
                    CC_SHA1_DIGEST_LENGTH,
                    [rawCipher bytes],
                    [rawCipher length]);
    
    return (status == noErr);
    
}

- (NSString *) sign: (NSData *) input {
    
    if (privateKeyRef == nil || keyLength == 0)
        return nil;
    
    /* Hash */
    unsigned char digtmp[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1([input bytes], (CC_LONG) [input length], digtmp);
    
    
    unsigned char * output = (unsigned char *) malloc(keyLength);
    
	size_t outputSize = keyLength;

    OSStatus status = SecKeyRawSign(privateKeyRef,
							   kSecPaddingPKCS1SHA1,
							   digtmp,
							   CC_SHA1_DIGEST_LENGTH,
							   output,
							   &outputSize);
	
	if (status != noErr || outputSize != keyLength) {
		NSLog(@"Sign operation failed");
		return nil;
	}
	
	NSString * ret;
	Base64 * base64 = [[Base64 alloc] init];
	ret = [base64 base64encode:[[NSData alloc] initWithBytes:output length:outputSize] length:(int) outputSize];
	
	return ret;
    
}



#pragma mark -
#pragma mark Useful Functions

- (int) getKeyLength {
    
    return keyLength;
}


@end

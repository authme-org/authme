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
//  KeyChainPasssword.m
//  AuthMe
//
//  Created by Berin Lautenbach on 20/02/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KeyChainPassword.h"

@implementation KeyChainPassword

- (id) initWithIdentifier: (NSString *) ident {
    
    if ((self = [super init]) != nil) {
        
        /* Allocate and clear the key */
        passwordIdentifier = [[NSString alloc] initWithFormat:@"%@.%@", ident, @".authmePassword"];
        
    }
    
    return (self);
}


- (BOOL) storeKey {
    
    CFErrorRef error = NULL;
    
    SecAccessControlRef sacObject =
        SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlUserPresence, &error);
    
    NSError * nsErr = (__bridge NSError *) error;
    if (nsErr != nil) {
        return FALSE;
    }
    
    /* First delete any existing password  - ignoring errors*/
    NSMutableDictionary * queryPassword = [[NSMutableDictionary alloc] init];
    
    [queryPassword setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [queryPassword setObject:passwordIdentifier forKey:(__bridge id)kSecAttrService];
    
    SecItemDelete((__bridge CFDictionaryRef) queryPassword);
    
    /* Now store the new password */
    
    NSData * toStore = [[NSData alloc] initWithBytes:password length:strlen(password)];
    
    [queryPassword setObject:toStore forKey:(__bridge id)kSecValueData];
    [queryPassword setObject:(__bridge id) sacObject forKey: (__bridge id) kSecAttrAccessControl];
    
    OSStatus err = SecItemAdd((__bridge CFDictionaryRef)queryPassword, nil);
    
    if (err != noErr) {
        return FALSE;
    }
    
    return TRUE;

    
}
- (BOOL) loadKey {
    
    CFTypeRef passwordRef;
    
    // build the query parameters
    NSMutableDictionary * queryPassword = [[NSMutableDictionary alloc] init];
    
    [queryPassword setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [queryPassword setObject:passwordIdentifier forKey:(__bridge id)kSecAttrService];
    [queryPassword setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    [queryPassword setObject:@"Authenticate to load keys" forKey:(__bridge id)kSecUseOperationPrompt];
    
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)queryPassword, (CFTypeRef *)&passwordRef);
    
    if (err != noErr || passwordRef == nil) {
        passwordRef = nil;
        return FALSE;
    }
    
    NSData * pwData = (__bridge NSData *) passwordRef;
    
    NSString * pwString = [[NSString alloc] initWithData:pwData encoding:NSUTF8StringEncoding];
    if (pwString != NULL) {
        password = strdup([pwString UTF8String]);
    }

    return TRUE;
    
}

/*
 * Determine if touchId is enabled to allow us to store the key
 */

- (BOOL) canStoreKey {
    
    return TRUE;
}

/* Password load/retrieve */

- (void) setPassword: (NSString *) toSet {
    
    if (toSet == NULL)
        return;
    
    if (password != NULL)
        free(password);
    
    password = strdup([toSet UTF8String]);
    
}

- (NSString *) getPassword {
    
    if (password == NULL)
        return NULL;
    
    return [[NSString alloc] initWithUTF8String:password];
    
}


@end

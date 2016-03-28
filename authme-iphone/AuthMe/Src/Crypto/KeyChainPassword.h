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
//  KeyChainPassword.h
//  AuthMe
//
//  Created by Berin Lautenbach on 20/02/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

#ifndef KeyChainPassword_h
#define KeyChainPassword_h


@interface KeyChainPassword : NSObject {
    
    char * password;
    NSString * passwordIdentifier;
}

- (id) initWithIdentifier: (NSString *) ident;

/*
 * Methods to store and retrieve the password under the user's device password
 */


- (BOOL) storeKey;
- (BOOL) loadKey;

/*
 * Determine if touchId is enabled to allow us to store the key
 */

- (BOOL) canStoreKey;

/*
 * Get and set the password
 */

- (NSString *) getPassword;
- (void) setPassword: (NSString *) toSet;

@end

#endif /* KeyChainPassword_h */

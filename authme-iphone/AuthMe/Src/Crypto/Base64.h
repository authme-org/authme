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
//  Base64.h
//  AuthMe
//
//  Created by Berin Lautenbach on 17/03/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface Base64 : NSObject {

	int lineLength;
}

/*
 * Methods to encode and decode a single buffer
 * Returns a NSMutableData to avoid char buffers hanging around the
 * place
 */
 
//- (NSMutableString *) base64encode: (const unsigned char *) rawInput length: (int) length;
//- (NSMutableData *) base64decode: (const char *) encodedInput length: (int) length;

- (NSMutableString *) base64encode: (NSData *) rawInput length: (int) length;
- (NSMutableData *) base64decode: (NSString *) encodedInput length: (int) length;


@end

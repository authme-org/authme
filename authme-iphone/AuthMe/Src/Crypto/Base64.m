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
//  Base64.m
//  AuthMe
//
//  Created by Berin Lautenbach on 17/03/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "Base64.h"

static char encodingTable[64] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
	'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
	'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
	'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/' };

@implementation Base64

- (id) init {

	if (self = [super init]) {
		lineLength = 0;
	}
	return (self);
}

#pragma mark Interface

- (NSMutableString *) base64encode: (NSData *) rawInput length: (int) length {
    return [self rawBase64encode:[rawInput bytes] length:length];
    
    
}
- (NSMutableData *) base64decode: (NSString *) encodedInput length: (int) length {
    
    return [self rawBase64decode:[encodedInput UTF8String] length:length];
}


#pragma mark Internals

- (NSMutableString *) rawBase64encode: (const unsigned char *) rawInput
							length: (int) length
{

	// Counters
	int ixRawInput = 0;
	int i, ix, ctremaining, ctcopy, charsonline;
	// Buffers
	unsigned char inbuf[3], outbuf[4];
	// Return
	NSMutableString *result = [NSMutableString stringWithCapacity:(int) (((length / 3) * 4) + 4)];

	
	ctremaining = 0;
	charsonline = 0;
	
	while (length - ixRawInput > 0) {
		
		ctremaining = length - ixRawInput;
		
		for( i = 0; i < 3; i++ ) {
			ix = ixRawInput + i;
			if( ix < length ) 
				inbuf[i] = rawInput[ix];
			else 
				inbuf [i] = 0;
		}
		
		outbuf [0] = (inbuf [0] & 0xFC) >> 2;
		outbuf [1] = ((inbuf [0] & 0x03) << 4) | ((inbuf [1] & 0xF0) >> 4);
		outbuf [2] = ((inbuf [1] & 0x0F) << 2) | ((inbuf [2] & 0xC0) >> 6);
		outbuf [3] = inbuf [2] & 0x3F;
		ctcopy = 4;
		
		switch( ctremaining ) {
			case 1:
				ctcopy = 2;
				break;
			case 2:
				ctcopy = 3;
				break;
		}
		
		for( i = 0; i < ctcopy; i++ )
			[result appendFormat:@"%c", encodingTable[outbuf[i]]];
		
		for( i = ctcopy; i < 4; i++ )
			[result appendString:@"="];
		
		ixRawInput += 3;
		charsonline += 4;
		
		if( lineLength > 0 ) {
			if( charsonline >= lineLength ) {
				charsonline = 0;
				[result appendString:@"\n"];
			}
		}
	}
	
	return (result);
}

- (NSMutableData *) rawBase64decode: (const char *) encodedInput
						  length: (int) length
{
	int i, j, ixinbuf;
	unsigned char ch;
	// Working buffers
	unsigned char inbuf[4], outbuf[3];
	// Flags
	BOOL flignore, flendtext;
	// Return
	NSMutableData *mutableData = [NSMutableData dataWithCapacity:length];
	
	flendtext = NO;
	i = 0;
	ixinbuf = 0;	// No bytes yet translated
	
	while (i < length) {
			
		ch = encodedInput[i++];
		flignore = NO;
	
		// Is this something we can decode?
		if( ( ch >= 'A' ) && ( ch <= 'Z' ) ) ch = ch - 'A';
		else if( ( ch >= 'a' ) && ( ch <= 'z' ) ) ch = ch - 'a' + 26;
		else if( ( ch >= '0' ) && ( ch <= '9' ) ) ch = ch - '0' + 52;
		else if( ch == '+' ) ch = 62;
		else if( ch == '=' ) flendtext = YES;
		else if( ch == '/' ) ch = 63;
		else flignore = YES;
	
		if( ! flignore ) {
			short ctcharsinbuf = 3;
			BOOL flbreak = NO;
		
			if( flendtext ) {
				if( ! ixinbuf ) 
					break;
				if( ( ixinbuf == 1 ) || ( ixinbuf == 2 ) ) 
					ctcharsinbuf = 1;
				else 
					ctcharsinbuf = 2;
				ixinbuf = 3;
				flbreak = YES;
			}
		
			inbuf [ixinbuf++] = ch;
		
			if( ixinbuf == 4 ) {
				ixinbuf = 0;
				outbuf [0] = ( inbuf[0] << 2 ) | ( ( inbuf[1] & 0x30) >> 4 );
				outbuf [1] = ( ( inbuf[1] & 0x0F ) << 4 ) | ( ( inbuf[2] & 0x3C ) >> 2 );
				outbuf [2] = ( ( inbuf[2] & 0x03 ) << 6 ) | ( inbuf[3] & 0x3F );
			
				for( j = 0; j < ctcharsinbuf; j++ )
					[mutableData appendBytes:&outbuf[j] length:1];
			}
		
			if( flbreak )  
				break;
		}
	
	}
	return mutableData;
}

@end

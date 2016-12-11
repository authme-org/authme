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
//  CryptoTests.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 25/02/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

import UIKit
import XCTest

class CryptoTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testBase64() {
        
        // Base64 test vectors
        let inputTest1 = "foob"
        let outputTest1 = "Zm9vYg=="
        
        let inputTest2 = "fooba"
        let outputTest2 = "Zm9vYmE="
        
        let inputTest3 = "foobar"
        let outputTest3 = "Zm9vYmFy"
        
        let b64 = Base64()
        
        // Encode tests
        
        let resultTest1 = b64.base64encode(inputTest1.data(using: String.Encoding.utf8, allowLossyConversion: false), length: Int32(inputTest1.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest1, outputTest1, "Test one in Base64 failed");
        let resultTest2 = b64.base64encode(inputTest2.data(using: String.Encoding.utf8, allowLossyConversion: false), length: Int32(inputTest2.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest2, outputTest2, "Test two in Base64 failed");
        let resultTest3 = b64.base64encode(inputTest3.data(using: String.Encoding.utf8, allowLossyConversion: false), length: Int32(inputTest3.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest3, outputTest3, "Test three in Base64 failed");
        
        // decode tests
        let resultTest11 = b64.base64decode(outputTest1, length: Int32(outputTest1.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest11, inputTest1.data(using: String.Encoding.utf8, allowLossyConversion: false)!, "Decode test 1 failed")
        let resultTest12 = b64.base64decode(outputTest2, length: Int32(outputTest2.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest12, inputTest2.data(using: String.Encoding.utf8, allowLossyConversion: false)!, "Decode test 2 failed")
        let resultTest13 = b64.base64decode(outputTest3, length: Int32(outputTest3.lengthOfBytes(using: String.Encoding.utf8)))
        XCTAssertEqual(resultTest13, inputTest3.data(using: String.Encoding.utf8, allowLossyConversion: false)!, "Decode test 3 failed")
        
    }
    
    func testAES() {
        
        let raw = "The quick brown fox"
        let rawData = raw.data(using: String.Encoding.utf8, allowLossyConversion: true)
        XCTAssertNotNil(rawData, "rawData is nil")
        let rawLength = UInt(rawData!.count)
        
        let aes = AESKey()
        XCTAssertTrue(aes.generateKey(), "Error generating key")
        let b64 = Base64()
        
        let encrypted = aes.encrypt(rawData!, plainLength: size_t(rawLength))
        let rawEncrypted = b64.base64decode(encrypted, length: Int32((encrypted?.lengthOfBytes(using: String.Encoding.utf8))!))
        
        XCTAssertEqual(rawEncrypted?.length, 48, "Incorrect length of encrypted data")
        
        // Decrypt
        let decrypt = aes.decrypt(encrypted, cipherLength: size_t((encrypted?.lengthOfBytes(using: String.Encoding.utf8))!))
        let decryptString = NSString(data: decrypt, encoding: String.Encoding.utf8) as! String
        XCTAssertEqual(decryptString as String, raw, "Decrypt / Encrypt mismatch for AES")
        
        
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure() {
            // Put the code you want to measure the time of here.
        }
    }
    
}

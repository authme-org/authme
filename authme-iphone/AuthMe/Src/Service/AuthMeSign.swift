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
//  AuthMeSign.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 30/01/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

import Foundation

class AuthMeSign : AuthMeServiceDelegate {
    
    var logger = Log()
    
    var sigId = ""
    var dateTime = ""
    var signature = ""
    var toSign = ""
    var delegate: AuthMeSignDelegate? = nil
    var opaqueData: AnyObject? = nil
    
    var keyPair : RSAKey? = nil
    
    var masterPassword: MasterPassword
    var authme: AuthMeService
    
    init() {
        masterPassword = MasterPassword.getInstance()
        authme = AuthMeService()
    }

    func doSign(_ toSign: String, keyPair: RSAKey, delegate: AuthMeSignDelegate, withOpaqueData opaqueData: AnyObject?) {
        self.toSign = toSign
        self.keyPair = keyPair
        self.delegate = delegate
        self.opaqueData = opaqueData
        
        if self.keyPair == nil {
            return
        }
        
        authme.getSignatureSeed(self, withOpaqueData: opaqueData)
        
    }
    
    
    func service(_ service: AuthMeService, didCompletOperation operation: AuthMeServiceOperation, withOpaqueData opaqueData: AnyObject?) {
        
        if operation.operationType != AuthMeService.AuthMeOperationType.getSignatureSeed {
            logger.log(.error, message: "Somehow got a authme return that isn't a signature seed into a signer object")
                return
        }
        
        var success = false
        
        if operation.statusCode == 200 {
            if let readData = operation.returnData {
                let json = (try! JSONSerialization.jsonObject(with: readData as Data, options: JSONSerialization.ReadingOptions.mutableContainers)) as! NSDictionary
                if (json.object(forKey: "sigId") as? NSString != nil) && (json.object(forKey: "dateTime") as? NSString != nil) {
                    sigId = json.value(forKey: "sigId") as! String
                    dateTime = json.value(forKey: "dateTime") as! String
                    
                    if keyPair != nil {
                        //signature = keyPair!.sign("\(sigId)\(toSign)".dataUsingEncoding(NSUTF8StringEncoding))
                        signature = keyPair!.sign("\(sigId)\(dateTime)\(toSign)".data(using: String.Encoding.utf8))
                        success = true
                    }
                }
            }
        }
        
        self.delegate?.signerDidComplete(self, didSucceed: success, withOpaqueData: opaqueData)
    }
    
}

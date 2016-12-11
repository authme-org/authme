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
//  SvcSession.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 9/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

class SvcSession {
    
    var status = ""
    var checkId = ""
    var serverId = ""
    var serverNonce = ""
    var serverDate = ""
    var serverString = ""
    var wrappedSecret = ""
    var unwrappedSecret = ""
    var serverNSDate : Date

    init(json: NSDictionary) {
        
        if let statusIn = json.object(forKey: "status") as? NSString {
            status = statusIn as String
        }
        if let checkIdIn = json.object(forKey: "checkId") as? NSString {
            checkId = checkIdIn as String
        }
        if let serverIdIn = json.object(forKey: "serverId") as? NSString {
            serverId = serverIdIn as String
        }
        if let serverNonceIn = json.object(forKey: "serverNonce") as? NSString {
            serverNonce = serverNonceIn as String
        }
        if let serverDateIn = json.object(forKey: "serverDate") as? NSString {
            serverDate = serverDateIn as String
        }
        if let serverStringIn = json.object(forKey: "serverString") as? NSString {
            serverString = serverStringIn as String
        }
        if let unwrappedSecretIn = json.object(forKey: "unwrappedSecret") as? NSString {
            unwrappedSecret = unwrappedSecretIn as String
        }
        if let wrappedSecretIn = json.object(forKey: "wrappedSecret") as? NSString {
            wrappedSecret = wrappedSecretIn as String
        }
        
        serverNSDate = SvcSession.dateFromAuthMeString(serverDate)
    }
    
    class func dateFromAuthMeString(_ str: String) -> Date {
    
        /* Convert an input string from the service to a date */
        /* Example date: Mon May 09 19:06:57 EST 2011 */
    
        // Convert string to date object
        let dateFormat = DateFormatter()
        dateFormat.dateFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
        if let ret = dateFormat.date(from: str) {
            return ret
        }
        
        return Date()
    
    }
}

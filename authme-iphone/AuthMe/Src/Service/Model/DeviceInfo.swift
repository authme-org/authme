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
//  DeviceInfo.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 31/01/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

import Foundation

class DeviceInfo {
    
    var apnToken = ""
    var c2dmToken = ""
    var deviceUniqueId = ""
    var encryptedData = ""
    var isSelected = false
    var name = ""
    var ownerUserId = ""
    var publicKey = ""
    var serviceKeyStatus = ""
    var type = ""
    var validated = false
    
    func jsonReader(json: NSDictionary, key: String) -> String {
        if let inString = json.objectForKey(key) as? NSString {
            return inString as String
        }
        
        return ""
    }
    
    init(json: NSDictionary) {
        
        apnToken = jsonReader(json, key: "apnToken")
        c2dmToken = jsonReader(json, key: "c2dmToken")
        deviceUniqueId = jsonReader(json, key: "deviceUniqueId")
        encryptedData = jsonReader(json, key: "encryptedData")
        name = jsonReader(json, key: "name")
        ownerUserId = jsonReader(json, key: "ownerUserId")
        publicKey = jsonReader(json, key: "publicKey")
        serviceKeyStatus = jsonReader(json, key: "serviceKeyStatus")
        type = jsonReader(json, key: "type")

        if let inBool = json.objectForKey("validated") as? Bool {
            validated = inBool
        }
        if let inBool = json.objectForKey("isSelected") as? Bool {
            isSelected = inBool
        }
    }
    
}
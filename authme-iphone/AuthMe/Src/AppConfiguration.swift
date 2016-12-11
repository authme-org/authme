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
//  Configuration.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 30/01/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

import Foundation
import CoreData
import Security
import UIKit

/* Until class variables are supported */
private let  _singletonConfiguration: AppConfiguration = AppConfiguration()

class AppConfiguration {
    
    var logger = Log()
    
    let servicePlistFile = "ServiceConfig"
    
    // Constants to look up service elements
    let baseURLKey = "BaseURL"
    let entryPointsKey = "EntryPoints"
    let updateArticleKey = "UpdateArticle"
    
    // THis is a hack until the do something with core data to let you check
    // if a key exists.  Under Objective C we used to be able to catch the
    // exception (still a hack I suppose :( )
    
    let knownConfigKeys = ["serviceUsername", "serviceURL", "servicePassword", "apnToken"]
    
    var cachedConfig: AuthMeConfiguration? = nil
    var rootViewController: UIViewController? = nil
        
    var managedObjectContext: NSManagedObjectContext? = nil {
        
        didSet {
            
            // When this is set we load our initial config
            let fetchRequest = NSFetchRequest<NSFetchRequestResult>()
            let entity =
            NSEntityDescription.entity(forEntityName: "AuthMeConfiguration", in: managedObjectContext!)
            fetchRequest.entity = entity
            
            var fetchResult: [AnyObject] = []
            
            do {
                fetchResult = try managedObjectContext!.fetch(fetchRequest) as [AnyObject]!
            } catch _ {
            }
            
            /* Can we fetch the required class from the store? */
            if fetchResult.count == 0 {
                
                // Oh dear - need to create from scratch
                logger.log(.info, message: "Creating default configuration")
                cachedConfig = NSEntityDescription.insertNewObject(forEntityName: "AuthMeConfiguration", into: managedObjectContext!) as? AuthMeConfiguration
                self.setDefaultValues()
                do {
                    try managedObjectContext?.save()
                } catch _ {
                }
            }
            else {
                cachedConfig = fetchResult[0] as? AuthMeConfiguration
            }
        }
    }
    
    
    class func getInstance() -> AppConfiguration {
        
        /* Check we are on the main thread.  Simple thread safety :) */
        assert(Thread.isMainThread, "Error: Config must be called on main thread")
        
        return _singletonConfiguration
        
    }
    
    // MARK: Get/Set
    
    func getConfigItem(_ key: NSString) -> AnyObject? {
        
        if cachedConfig == nil {
            return nil
        }
        
        /* Check we are on the main thread.  Simple thread safety :) */
        assert(Thread.isMainThread, "Error: Config must be called on main thread")
        
        var result: AnyObject? = nil
        
        if checkKeyIsValid(key) {
            
            result = cachedConfig!.value(forKey: key as String) as AnyObject?
        }
        
        return result
        
    }
    
    func setConfigItem(_ key: NSString, value: AnyObject?) {
        
        if cachedConfig == nil {
            return
        }
        
        /* Check we are on the main thread.  Simple thread safety :) */
        assert(Thread.isMainThread, "Error: Config must be called on main thread")
        
        if checkKeyIsValid(key) {
            
            cachedConfig?.setValue(value, forKey: key as String)
            do {
                try managedObjectContext?.save()
            } catch _ {
            }
        }
        
    }
    
    
    fileprivate func setDefaultValues() {
        
        // By default we assume we are not registered on this device
        cachedConfig?.registered = 0
        
        // Empty username/password
        cachedConfig?.servicePassword = ""
        cachedConfig?.serviceUsername = ""
        cachedConfig?.serviceURL = "http://pluto.wingsofhermes.org:8080/AuthMeWS/Svc"
        
        // Get the base url from the service configuration
        #if DEBUG
            if let serviceBase = servicePlist.value(forKey: "BaseURLDebug") as? NSString {
                cachedConfig?.serviceURL = serviceBase as String
            }
            else {
                cachedConfig?.serviceURL = "http://pluto:8080/AuthMeWS/Svc"
            }
        #else
            if let serviceBase = servicePlist.value(forKey: "BaseURL") as? NSString {
                cachedConfig?.serviceURL = serviceBase as String
            }
            else {
                cachedConfig?.serviceURL = "https://www.readercom.com/readercom/"
            }
        #endif
        
    }
    
    // MARK: Password Handling
    
    func setServicePassword(_ password: NSString) {
        
        let masterPassword = MasterPassword.getInstance()
        if masterPassword.storeKey != nil {
            
            /* Encrypt the key */
            if let passwordAsData = password.data(using: String.Encoding.utf8.rawValue) {
                let encryptedPassword = masterPassword.storeKey!.encrypt(passwordAsData, plainLength: passwordAsData.count)
                setConfigItem("servicePassword", value: encryptedPassword as AnyObject?)
            }
        }
    }
    
    func getServicePassword() -> String {
        
        if let encryptedPassword = getConfigItem("servicePassword") as? String {
            let masterPassword = MasterPassword.getInstance()
            if masterPassword.storeKey != nil {
                if let decryptedPassword = masterPassword.storeKey?.decrypt(encryptedPassword, cipherLength: encryptedPassword.characters.count) {
                    if let retString = NSString(data: decryptedPassword as Data, encoding: String.Encoding.utf8.rawValue) {
                        return retString as String
                    }
                }
            }
        }
        return ""
    }
    
    // MARK: Service properties
    func getServiceUrl(_ entryPoint: String) -> String {
        
        var base = cachedConfig!.value(forKey: "serviceURL") as? String
        
        if base == nil {
            base = servicePlist.value(forKey: baseURLKey) as? String
            if base == nil {
                return ""
            }
        }
        
        // Now find the appropriate relative URL for the entry point
        var relativeURL = ""
        if let entryPointsDict = servicePlist.value(forKey: entryPointsKey) as? NSDictionary {
            if let relURL = entryPointsDict.value(forKey: entryPoint) as? String {
                relativeURL = relURL
            }
        }
        
        let ret = base! + relativeURL
        return ret
        
    }
    
    func getNewUserUrl() -> String {
        
        #if DEBUG
            if let newUserUrl = servicePlist.value(forKey: "NewUserURLDebug") as? String {
                return newUserUrl
            }
            else {
                return "http://pluto:8080/readercom/new-user.ss"
            }
        #else
            if let newUserUrl = servicePlist.value(forKey: "NewUserURL") as? NSString {
                return newUserUrl as String;
            }
            else {
                return "https://www.readercom.com/readercom/new-user.html"
            }
        #endif
        
    }
    
    // MARK: Helper functions
    fileprivate func checkKeyIsValid(_ key: NSString) -> Bool {
        
        for knownKey in knownConfigKeys {
            if knownKey == key as String {
                return true
            }
        }
        
        return false
    }
    
    // MARK: Load the service PLIST
    var servicePlist: NSDictionary {
        
        if _servicePlist != nil {
            return _servicePlist!
        }
        
        if let servicePath = Bundle.main.path(forResource: servicePlistFile, ofType: "plist") {
            _servicePlist = NSDictionary(contentsOfFile: servicePath)
        }
        else {
            _servicePlist = NSDictionary()
        }
        return _servicePlist!
        
    }
    
    var _servicePlist: NSDictionary? = nil
    
}

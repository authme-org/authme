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
//  AuthMeService.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 8/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

class AuthMeService : NSObject {
    
    let servicePlistFile = "ServiceConfig"
    
    enum AuthMeOperationType : Int {
        case unknownOperation = 0
        case addDevice = 1
        case getDevice = 2
        case getServiceKey = 3
        case getAuthChecks = 4
        case getSignatureSeed = 5
        case setAuthCheckStatus = 6
        case setServiceKey = 7
        case getDevices = 8
    }
    
    var queue: OperationQueue? = nil
    var logger = Log()
    
    //MARK: Setup and reset
    
    override
    init() {
        
        super.init()
        
        /* Create the operations queue */
        self.queue = OperationQueue()
        if let q = self.queue {
            q.maxConcurrentOperationCount = 4;
        }
    }
    
    func cancelAll() {
        queue?.cancelAllOperations()
    }

    // MARK: Service Calls
    @discardableResult
    func addDevice(
        _ deviceUniqueId : String,
        withName name: String,
        withType deviceType: String,
        withAPNToken apnToken: String?,
        withPublicKey publicKey: String,
        withDelegate delegate: AuthMeServiceDelegate?) -> Bool
    {
    
        logger.log(.debug, message: "AddDevice called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("AddDevice")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
    
        // Create the POST data
        let params = NSMutableDictionary(
            objects: [deviceUniqueId, deviceType, publicKey, name],
            forKeys: ["deviceUniqueId" as NSCopying, "type" as NSCopying, "publicKey" as NSCopying, "name" as NSCopying])
        
        /* Append APN data if we have it */
        if (apnToken != nil) && (apnToken != "") {
            params.setValue(apnToken, forKey: "apnToken")
        }
        
        if let postData = try? JSONSerialization.data(withJSONObject: params, options: JSONSerialization.WritingOptions(rawValue: 0)) {
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .addDevice
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false
    }
    
    @discardableResult
    func getDevice(_ deviceUniqueId: String,
        withNonce nonce: String,
        withOpaqueData opaque: AnyObject?,
        withDelegate delegate: AuthMeServiceDelegate) -> Bool
    {
        logger.log(.debug, message: "GetDevice called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("GetDevice") + "?deviceUniqueId=\(deviceUniqueId)&nonce=\(nonce)"
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = opaque
        operation.operationType = .getDevice
        operation.secureRequest = true
            
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
        queue?.addOperation(operation)
            
        return true
        
    }
    
    @discardableResult
    func getDevices(_ delegate: AuthMeServiceDelegate) -> Bool {
        logger.log(.debug, message: "GetDevices called")
        
        // Create the operation
        let url = getServiceEntryURL("GetDevices")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
        operation.postData = nil
        operation.operationType = .getDevices
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
        queue?.addOperation(operation)
        
        return true
        
    }
    
    @discardableResult
    func getServiceKey(_ deviceUniqueId: String,
        withDelegate delegate: AuthMeServiceDelegate) -> Bool
    {
        logger.log(.debug, message: "GetServiceKey called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("GetServiceKey") + "?deviceId=\(deviceUniqueId)"
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = nil
        operation.operationType = .getServiceKey
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
        queue?.addOperation(operation)
        
        return true
    }
    
    @discardableResult
    func getAuthChecks(_ delegate: AuthMeServiceDelegate) -> Bool {
        
        logger.log(.debug, message: "GetAuthChecks called")
        
        // Create the operation
        let url = getServiceEntryURL("AuthCheck")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = nil
        operation.operationType = .getAuthChecks
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
        queue?.addOperation(operation)
        
        return true
        
    }
    
    @discardableResult
    func getSignatureSeed(_ delegate: AuthMeServiceDelegate, withOpaqueData opaqueData: AnyObject?) -> Bool {
        
        logger.log(.debug, message: "GetSignatureSeed called")
        
        // Create the operation
        let url = getServiceEntryURL("SignatureSeed")
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = opaqueData
        operation.operationType = .getSignatureSeed
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
        queue?.addOperation(operation)
        
        return true
    }
    
    @discardableResult
    func setAuthCheckStatus(_ svcSession: SvcSession, withStatus status: String, withSignature signature:AuthMeSign, withUnwrappedSecret unwrappedSecret: String, delegate: AuthMeServiceDelegate) -> Bool {
        
        logger.log(.debug, message: "setAuthCheckStatus called")
        // Create the operation
        let url = getServiceEntryURL("AuthCheck")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        // Create the POST data
        
        // First a signature
        let sig = NSMutableDictionary(
            objects: [signature.sigId, signature.dateTime, signature.signature],
            forKeys: ["sigId" as NSCopying, "dateTime" as NSCopying, "value" as NSCopying])
        
        let params = NSMutableDictionary(
            objects: [svcSession.checkId, status, unwrappedSecret, sig],
            forKeys: ["checkId" as NSCopying,"status" as NSCopying,"unwrappedSecret" as NSCopying,"signature" as NSCopying])
        
        if let postData = try? JSONSerialization.data(withJSONObject: params, options: JSONSerialization.WritingOptions(rawValue: 0)) {
            operation.delegate = delegate
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .setAuthCheckStatus
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false

    }
    
    @discardableResult
    func setServiceKey(_ deviceId: String,
        encryptedKeyValue: String,
        keyKCV: String,
        encryptedPrivateKey: String,
        privateKVC: String,
        publicKey: String,
        signature: AuthMeSign,
        delegate: AuthMeServiceDelegate) -> Bool {
            
        logger.log(.debug, message: "setServiceKey called")
            
        // Create the operation
        let url = getServiceEntryURL("SetServiceKey")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url as NSString)
        // Create the POST data
        
        // First a signature
        let sig = NSMutableDictionary(
            objects: [signature.sigId, signature.dateTime, signature.signature],
            forKeys: ["sigId" as NSCopying, "dateTime" as NSCopying, "value" as NSCopying])
        
        let params = NSMutableDictionary(
            objects: [deviceId,
                encryptedKeyValue,
                keyKCV,
                encryptedPrivateKey,
                privateKVC,
                publicKey,
                sig],
            forKeys: ["deviceId" as NSCopying,
                "encryptedKeyValue" as NSCopying,
                "keyKCV" as NSCopying,
                "encryptedPrivateKey" as NSCopying,
                "privateKCV" as NSCopying,
                "publicKey" as NSCopying,
                "signature" as NSCopying
            ])
        
        if let postData = try? JSONSerialization.data(withJSONObject: params, options: JSONSerialization.WritingOptions(rawValue: 0)) {
            operation.delegate = delegate
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .setServiceKey
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.new, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false
        
    }

    
    // MARK: URL Handling
    @discardableResult
    func getServiceEntryURL(_ entryPoint: String) -> String {
        
        var base : String? = nil

        // First try from configuration
        #if DEBUG
            let doDebug = AppConfiguration.getInstance().getConfigItem("useDebugURL") as? NSNumber
            if  doDebug == 1 {
                if let configBase = AppConfiguration.getInstance().getConfigItem("serviceDebugURL") as? String {
                    if configBase != "" {
                        base = configBase
                    }
                }
            }
            else {
                if let configBase = AppConfiguration.getInstance().getConfigItem("serviceURL") as? String {
                    if configBase != "" {
                        base = configBase
                    }
                }
            }
        #else
            if let configBase = AppConfiguration.getInstance().getConfigItem("serviceURL") as? String {
                if configBase != "" {
                    base = configBase
                }
            }
        #endif
        
        if base == nil {
        
            #if DEBUG
                if doDebug == 1 {
                    base = servicePlist.value(forKey: "BaseURLDebug") as? String
                }
                else {
                    base = servicePlist.value(forKey: "BaseURL") as? String
                }
            #else
                base = servicePlist.value(forKey: "BaseURL") as? String
            #endif
        
            if base == nil {
                return ""
            }
        }
        
        // Now find the appropriate relative URL for the entry point
        var relativeURL = ""
        if let entryPointsDict = servicePlist.value(forKey: "EntryPoints") as? NSDictionary {
            if let relURL = entryPointsDict.value(forKey: entryPoint) as? String {
                relativeURL = relURL
            }
        }
        
        var ret = ""
        if base!.hasSuffix("/") {
            ret = base! + relativeURL
        }
        else {
            ret = base! + "/" + relativeURL
        }

        return ret
    }
    
    // MARK: Service Delegate Functions
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        
        logger.log(.debug, message: "Observed a service finish!")
        
        let operation = object as! AuthMeServiceOperation
        
        if operation.error != nil {
            logger.log(.warn, message: "Got an error: \(operation.error?.description ?? "Unknown")")
        }
        else {
            logger.log(.debug, message: "URL : \(String(describing: operation.url)) worked")
        }
        
        if operation.delegate != nil {
            operation.delegate!.service(self, didCompletOperation: operation, withOpaqueData: operation.opaqueData)
        }
        
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

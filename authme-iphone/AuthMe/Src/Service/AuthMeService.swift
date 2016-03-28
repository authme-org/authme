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
        case UnknownOperation = 0
        case AddDevice = 1
        case GetDevice = 2
        case GetServiceKey = 3
        case GetAuthChecks = 4
        case GetSignatureSeed = 5
        case SetAuthCheckStatus = 6
        case SetServiceKey = 7
        case GetDevices = 8
    }
    
    var queue: NSOperationQueue? = nil
    var logger = Log()
    
    //MARK: Setup and reset
    
    override
    init() {
        
        super.init()
        
        /* Create the operations queue */
        self.queue = NSOperationQueue()
        if let q = self.queue {
            q.maxConcurrentOperationCount = 4;
        }
    }
    
    func cancelAll() {
        queue?.cancelAllOperations()
    }

    // MARK: Service Calls
    
    func addDevice(
        deviceUniqueId : String,
        withName name: String,
        withType deviceType: String,
        withAPNToken apnToken: String?,
        withPublicKey publicKey: String,
        withDelegate delegate: AuthMeServiceDelegate?) -> Bool
    {
    
        logger.log(.DEBUG, message: "AddDevice called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("AddDevice")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
    
        // Create the POST data
        let params = NSMutableDictionary(
            objects: [deviceUniqueId, deviceType, publicKey, name],
            forKeys: ["deviceUniqueId", "type", "publicKey", "name"])
        
        /* Append APN data if we have it */
        if (apnToken != nil) && (apnToken != "") {
            params.setValue(apnToken, forKey: "apnToken")
        }
        
        if let postData = try? NSJSONSerialization.dataWithJSONObject(params, options: NSJSONWritingOptions(rawValue: 0)) {
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .AddDevice
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false
    }
    
    func getDevice(deviceUniqueId: String,
        withNonce nonce: String,
        withOpaqueData opaque: AnyObject?,
        withDelegate delegate: AuthMeServiceDelegate) -> Bool
    {
        logger.log(.DEBUG, message: "GetDevice called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("GetDevice") + "?deviceUniqueId=\(deviceUniqueId)&nonce=\(nonce)"
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = opaque
        operation.operationType = .GetDevice
        operation.secureRequest = true
            
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
        queue?.addOperation(operation)
            
        return true
        
    }
    
    func getDevices(delegate: AuthMeServiceDelegate) -> Bool {
        logger.log(.DEBUG, message: "GetDevices called")
        
        // Create the operation
        let url = getServiceEntryURL("GetDevices")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
        operation.postData = nil
        operation.operationType = .GetDevices
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
        queue?.addOperation(operation)
        
        return true
        
    }
    
    func getServiceKey(deviceUniqueId: String,
        withDelegate delegate: AuthMeServiceDelegate) -> Bool
    {
        logger.log(.DEBUG, message: "GetServiceKey called for device \(deviceUniqueId)")
        
        // Create the operation
        let url = getServiceEntryURL("GetServiceKey") + "?deviceId=\(deviceUniqueId)"
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = nil
        operation.operationType = .GetServiceKey
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
        queue?.addOperation(operation)
        
        return true
    }
    
    func getAuthChecks(delegate: AuthMeServiceDelegate) -> Bool {
        
        logger.log(.DEBUG, message: "GetAuthChecks called")
        
        // Create the operation
        let url = getServiceEntryURL("AuthCheck")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = nil
        operation.operationType = .GetAuthChecks
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
        queue?.addOperation(operation)
        
        return true
        
    }
    
    func getSignatureSeed(delegate: AuthMeServiceDelegate, withOpaqueData opaqueData: AnyObject?) -> Bool {
        
        logger.log(.DEBUG, message: "GetSignatureSeed called")
        
        // Create the operation
        let url = getServiceEntryURL("SignatureSeed")
        
        let operation = AuthMeServiceOperation(url: url)
        operation.delegate = delegate
        operation.postData = nil
        operation.opaqueData = opaqueData
        operation.operationType = .GetSignatureSeed
        operation.secureRequest = true
        
        operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
        queue?.addOperation(operation)
        
        return true
    }
    
    func setAuthCheckStatus(svcSession: SvcSession, withStatus status: String, withSignature signature:AuthMeSign, withUnwrappedSecret unwrappedSecret: String, delegate: AuthMeServiceDelegate) -> Bool {
        
        logger.log(.DEBUG, message: "setAuthCheckStatus called")
        // Create the operation
        let url = getServiceEntryURL("AuthCheck")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        // Create the POST data
        
        // First a signature
        let sig = NSMutableDictionary(
            objects: [signature.sigId, signature.dateTime, signature.signature],
            forKeys: ["sigId", "dateTime", "value"])
        
        let params = NSMutableDictionary(
            objects: [svcSession.checkId, status, unwrappedSecret, sig],
            forKeys: ["checkId","status","unwrappedSecret","signature"])
        
        if let postData = try? NSJSONSerialization.dataWithJSONObject(params, options: NSJSONWritingOptions(rawValue: 0)) {
            operation.delegate = delegate
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .SetAuthCheckStatus
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false

    }
    
    func setServiceKey(deviceId: String,
        encryptedKeyValue: String,
        keyKCV: String,
        encryptedPrivateKey: String,
        privateKVC: String,
        publicKey: String,
        signature: AuthMeSign,
        delegate: AuthMeServiceDelegate) -> Bool {
            
        logger.log(.DEBUG, message: "setServiceKey called")
            
        // Create the operation
        let url = getServiceEntryURL("SetServiceKey")
        if url == "" {
            return false
        }
        
        let operation = AuthMeServiceOperation(url: url)
        // Create the POST data
        
        // First a signature
        let sig = NSMutableDictionary(
            objects: [signature.sigId, signature.dateTime, signature.signature],
            forKeys: ["sigId", "dateTime", "value"])
        
        let params = NSMutableDictionary(
            objects: [deviceId,
                encryptedKeyValue,
                keyKCV,
                encryptedPrivateKey,
                privateKVC,
                publicKey,
                sig],
            forKeys: ["deviceId",
                "encryptedKeyValue",
                "keyKCV",
                "encryptedPrivateKey",
                "privateKCV",
                "publicKey",
                "signature"
            ])
        
        if let postData = try? NSJSONSerialization.dataWithJSONObject(params, options: NSJSONWritingOptions(rawValue: 0)) {
            operation.delegate = delegate
            operation.postData = postData
            operation.opaqueData = nil
            operation.operationType = .SetServiceKey
            operation.secureRequest = true
            
            operation.addObserver(self, forKeyPath: "isFinished", options: NSKeyValueObservingOptions.New, context: nil)
            queue?.addOperation(operation)
            
            return true
        }
        return false
        
    }

    
    // MARK: URL Handling
    func getServiceEntryURL(entryPoint: String) -> String {
        
        var base : String? = nil

        // First try from configuration
        if let configBase = AppConfiguration.getInstance().getConfigItem("serviceURL") as? String {
            if configBase != "" {
                base = configBase
            }
        }
        
        if base == nil {
        
            #if DEBUG
                base = servicePlist.valueForKey("BaseURLDebug") as? String
            #else
                base = servicePlist.valueForKey("BaseURL") as? String
            #endif
        
            if base == nil {
                return ""
            }
        }
        
        // Now find the appropriate relative URL for the entry point
        var relativeURL = ""
        if let entryPointsDict = servicePlist.valueForKey("EntryPoints") as? NSDictionary {
            if let relURL = entryPointsDict.valueForKey(entryPoint) as? String {
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
    
    override func observeValueForKeyPath(keyPath: String?, ofObject object: AnyObject?, change: [String : AnyObject]?, context: UnsafeMutablePointer<Void>) {
        
        logger.log(.DEBUG, message: "Observed a service finish!")
        
        let operation = object as! AuthMeServiceOperation
        
        if operation.error != nil {
            logger.log(.WARN, message: "Got an error: \(operation.error?.description)")
        }
        else {
            logger.log(.DEBUG, message: "URL : \(operation.url) worked")
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
        
        if let servicePath = NSBundle.mainBundle().pathForResource(servicePlistFile, ofType: "plist") {
            _servicePlist = NSDictionary(contentsOfFile: servicePath)
        }
        else {
            _servicePlist = NSDictionary()
        }
        return _servicePlist!
        
    }
    
    var _servicePlist: NSDictionary? = nil

}
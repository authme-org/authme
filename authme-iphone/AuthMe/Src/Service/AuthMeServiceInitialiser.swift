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
//  AuthMeServiceInitialiser.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 8/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

class AuthMeServiceInitialiser : NSObject, AuthMeServiceDelegate, AuthMeSignDelegate {
    
    var logger = Log()
    
    var initialised = false
    var masterPassword : MasterPassword
    var appConfiguration : AppConfiguration
    var authme : AuthMeService
    
    var serviceRSAKey : RSAKey? = nil
    var serviceAESKey : AESKey? = nil
    var serviceRSAKCV = ""
    var serviceAESKCV = ""
    
    var encryptedServicePrivateKey = ""
    var encryptedServiceAESKey = ""
    
    let _AUTHME_SERVICE_RSA_KEY_TAG = "org.authme.servicekeypair"
    
    override init() {
        masterPassword = MasterPassword.getInstance()
        authme = AuthMeService()
        appConfiguration = AppConfiguration.getInstance()
    }
    
    func doInit() {
        
        /* Would be wierd... */
        if initialised {
            return
        }
        
        logger.log(.DEBUG, message: "Starting init of authme service")
        
        /* First destroy any existing service configuration */
        masterPassword.serviceDeactivated()
        
        /* Add device is where we kick off from */
        authme.addDevice(
            masterPassword.getUniqueDeviceId(),
            withName: masterPassword.getDeviceName(),
            withType: "iPhone",
            withAPNToken: appConfiguration.getConfigItem("apnToken") as? String,
            withPublicKey: masterPassword.deviceRSAKey!.getPublicKey(),
            withDelegate: self)
        
    }
    
    func getDevice() {
        
        let date = NSDate()
        let df = NSDateFormatter()
        df.dateFormat = "dd/MM/yyyy-hh:mm:ssa"
        let nonce = df.stringFromDate(date)
        
        // Call the getDevice web service.  This will encrypt the nonce using the public key
        authme.getDevice(masterPassword.getUniqueDeviceId(), withNonce: nonce, withOpaqueData: nonce, withDelegate: self)
        
        return;
    }
    
    func checkDevice(json: NSDictionary, withNonce nonce: String) {
        logger.log(.DEBUG, message: "Validating device")
        
        if let encryptedData = json.objectForKey("encryptedData") as? NSString {
            if let decrypt = masterPassword.deviceRSAKey?.decrypt(encryptedData as String) {
                if let decryptString = NSString(data: decrypt, encoding: NSUTF8StringEncoding) {
                    if decryptString == nonce {
                        logger.log(.DEBUG, message: "Decrypt of nonce OK")
                        authme.getServiceKey(masterPassword.getUniqueDeviceId(), withDelegate: self)
                        return;
                    }
                }
            }
        }
        
        logger.log(.DEBUG, message: "device validation failed")
    }
    
    func uploadServiceKey() {
        logger.log(.DEBUG, message: "Sending service key to service");
        
        /* First have to sign it */
        let signature = AuthMeSign()
        signature.doSign(masterPassword.getUniqueDeviceId() + serviceAESKCV + encryptedServiceAESKey, keyPair: masterPassword.deviceRSAKey!, delegate: self, withOpaqueData: nil)
    }
    
    /* Worker task to create the RSA and AES service keys in the background */
    func createServiceKeyWorker() {
        
        /* Generate RSA key */
        
        logger.log(.DEBUG, message:"rsaGEnThreadMain now generating keys")
        
        serviceRSAKey = RSAKey(identifier: _AUTHME_SERVICE_RSA_KEY_TAG)
        if !serviceRSAKey!.generateKey(masterPassword._AUTHME_RSA_KEY_LENGTH * 8) {
            logger.log(.WARN, message: "Error generating RSA key")
            return
        }
        
        logger.log(.DEBUG, message: "RSA Service key generated")
        
        serviceAESKey = AESKey()
        if !serviceAESKey!.generateKey() {
            logger.log(.WARN, message: "Error generating AES key")
        }
        
        /* Now we encrypt the private key using the newly generated AES key */
        let rsaPrivateAsString = serviceRSAKey!.getPKCS8PrivateKey()
        let rsaPrivateAsData = NSData(base64EncodedString: rsaPrivateAsString, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)
        serviceRSAKey!.calculateKCV(rsaPrivateAsData)

        serviceRSAKCV = serviceRSAKey!.getKCV()
        serviceAESKCV = serviceAESKey!.getKCV()
        
        encryptedServicePrivateKey = serviceAESKey!.encrypt(rsaPrivateAsData, plainLength: rsaPrivateAsData!.length)
        
        /* Then the AES key under the device key */
        let aesKeyAsData = serviceAESKey!.getKeyAsData()
        encryptedServiceAESKey = masterPassword.deviceRSAKey!.encrypt(aesKeyAsData, plainLength: aesKeyAsData.length)
        
        logger.log(.DEBUG, message: "createServiceKeyWorker finalising");
        
        dispatch_async(dispatch_get_main_queue(), {self.uploadServiceKey()} )

    }
    
    func loadServiceKey(json: NSDictionary) {
        
        if let keyStatus = json.objectForKey("keyStatus") as? NSString {
            if keyStatus == "Available" {
                logger.log(.DEBUG, message: "Service Key available")
                if let encryptedKeyValue = json.objectForKey("encryptedKeyValue") as? NSString {
                    
                    let keyKCV = json.objectForKey("keyKCV") as? NSString
                    
                    // Decrypt...
                    if let serviceKeyRaw = masterPassword.deviceRSAKey?.decrypt(encryptedKeyValue as String) {
                        let serviceKey = AESKey()
                        if serviceKey.loadKey(serviceKeyRaw) && serviceKey.checkKCV(keyKCV as! String) {
                            logger.log(.DEBUG, message: "ServiceKey loaded")
                            masterPassword.serviceKey = serviceKey
                            loadServiceKeyPair(json)
                            return;
                        }
                    }
                }
            }
            
            else if keyStatus == "None" {
                logger.log(.DEBUG, message: "Service key not set - need to create one")
                /* Start a background threat to generate new keys */
                let createServiceWorkerThread = NSThread(target: self, selector: #selector(AuthMeServiceInitialiser.createServiceKeyWorker), object: nil)
                createServiceWorkerThread.start()
                return
            }
        }
        
        logger.log(.DEBUG, message: "Load of service key failed")
        
    }
    
    func loadServiceKeyPair(json: NSDictionary) {
        
        if let encryptedPrivateKey = json.objectForKey("encryptedPrivateKey") as? NSString {
            if let publicKey = json.objectForKey("publicKey") as? NSString {
                let privateKCV = json.objectForKey("privateKCV") as? NSString
                
                // Decrypt the private key
                if let decryptedPrivateKey = masterPassword.serviceKey?.decrypt(encryptedPrivateKey as String, cipherLength: 0) {
                    let k = RSAKey(identifier: _AUTHME_SERVICE_RSA_KEY_TAG)
                    if k.loadPKCS8PrivateKey(decryptedPrivateKey) &&
                        k.compareKCV(privateKCV as! String)
                    {
                        if k.loadPublicKey(publicKey as String) {
                            masterPassword.serviceKeyPair = k
                            logger.log(.DEBUG, message: "Service Key Pair loaded")
                            masterPassword.serviceActivated()
                            return
                        }
                    }
                }
                    
            }
        }
        
        logger.log(.WARN, message: "Failed to load service key pair")
        
    }
    
    func stateMachine(operation: AuthMeServiceOperation) {
        
        // This basically works through each of the steps to initialise
        
        switch operation.operationType {
            
        case .AddDevice:
            logger.log(.DEBUG, message: "Add Device Returned")
            if operation.statusCode == 200 || operation.statusCode == 201 {
                // Good to continue
                getDevice()
            }
            
        case .GetDevice:
            logger.log(.DEBUG, message: "Get Device Returned")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    let json = (try! NSJSONSerialization.JSONObjectWithData(readData, options: NSJSONReadingOptions.MutableContainers)) as! NSDictionary
                    checkDevice(json, withNonce: operation.opaqueData as! String)
                }
            }
            
        case .GetServiceKey:
            logger.log(.DEBUG, message: "Get Service Key Returned")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    let json = (try! NSJSONSerialization.JSONObjectWithData(readData, options: NSJSONReadingOptions.MutableContainers)) as! NSDictionary
                    loadServiceKey(json)
                }
            }
            
        case .SetServiceKey:
            logger.log(.DEBUG, message: "Set service key returned")
            if operation.statusCode == 201 {
                logger.log(.DEBUG, message: "Service key created!")
                masterPassword.serviceKey = serviceAESKey
                masterPassword.serviceKeyPair = serviceRSAKey
                masterPassword.serviceActivated()
            }
            else {
                logger.log(.WARN, message: "Set Service key failed - error \(operation.statusCode)")
            }
            
        default:
            logger.log(.ERROR, message: "Unknown service operation returned!")
        }
    }
    
    func service(service: AuthMeService, didCompletOperation operation: AuthMeServiceOperation, withOpaqueData opaqueData: AnyObject?) {
        
        logger.log(.DEBUG, message: "Service return")
        stateMachine(operation)
        
    }
    
    func signerDidComplete(signer: AuthMeSign, didSucceed: Bool, withOpaqueData opaqueData: AnyObject?) {
        logger.log(.DEBUG, message: "Signer returned")
        
        authme.setServiceKey(masterPassword.getUniqueDeviceId(),
            encryptedKeyValue: encryptedServiceAESKey,
            keyKCV: serviceAESKCV,
            encryptedPrivateKey: encryptedServicePrivateKey,
            privateKVC: serviceRSAKCV,
            publicKey: serviceRSAKey!.getPublicKey(),
            signature: signer, delegate: self)
        
    }
    
}
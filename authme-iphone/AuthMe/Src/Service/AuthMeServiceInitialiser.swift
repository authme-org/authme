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
        
        logger.log(.debug, message: "Starting init of authme service")
        
        /* First destroy any existing service configuration */
        masterPassword.serviceDeactivated()
        
        /* Add device is where we kick off from */
        _ = authme.addDevice(
            masterPassword.getUniqueDeviceId(),
            withName: masterPassword.getDeviceName(),
            withType: "iPhone",
            withAPNToken: appConfiguration.getConfigItem("apnToken") as? String,
            withPublicKey: masterPassword.deviceRSAKey!.getPublicKey(),
            withDelegate: self)
        
    }
    
    func getDevice() {
        
        let date = Date()
        let df = DateFormatter()
        df.dateFormat = "dd/MM/yyyy-hh:mm:ssa"
        let nonce = df.string(from: date)
        
        // Call the getDevice web service.  This will encrypt the nonce using the public key
        _ = authme.getDevice(masterPassword.getUniqueDeviceId(), withNonce: nonce, withOpaqueData: nonce as AnyObject?, withDelegate: self)
        
        return;
    }
    
    func checkDevice(_ json: NSDictionary, withNonce nonce: String) {
        logger.log(.debug, message: "Validating device")
        
        if let encryptedData = json.object(forKey: "encryptedData") as? NSString {
            if let decrypt = masterPassword.deviceRSAKey?.decrypt(encryptedData as String) {
                if let decryptString = NSString(data: decrypt, encoding: String.Encoding.utf8.rawValue) {
                    if decryptString as String == nonce {
                        logger.log(.debug, message: "Decrypt of nonce OK")
                        _ = authme.getServiceKey(masterPassword.getUniqueDeviceId(), withDelegate: self)
                        return;
                    }
                }
            }
        }
        
        logger.log(.debug, message: "device validation failed")
    }
    
    func uploadServiceKey() {
        logger.log(.debug, message: "Sending service key to service");
        
        /* First have to sign it */
        let signature = AuthMeSign()
        signature.doSign(masterPassword.getUniqueDeviceId() + serviceAESKCV + encryptedServiceAESKey, keyPair: masterPassword.deviceRSAKey!, delegate: self, withOpaqueData: nil)
    }
    
    /* Worker task to create the RSA and AES service keys in the background */
    @objc func createServiceKeyWorker() {
        
        /* Generate RSA key */
        
        logger.log(.debug, message:"rsaGEnThreadMain now generating keys")
        
        serviceRSAKey = RSAKey(identifier: _AUTHME_SERVICE_RSA_KEY_TAG)
        if !serviceRSAKey!.generate(masterPassword._AUTHME_RSA_KEY_LENGTH * 8) {
            logger.log(.warn, message: "Error generating RSA key")
            return
        }
        
        logger.log(.debug, message: "RSA Service key generated")
        
        serviceAESKey = AESKey()
        if !serviceAESKey!.generateKey() {
            logger.log(.warn, message: "Error generating AES key")
        }
        
        /* Now we encrypt the private key using the newly generated AES key */
        let rsaPrivateAsString = serviceRSAKey!.getPKCS8PrivateKey()
        let rsaPrivateAsData = Data(base64Encoded: rsaPrivateAsString!, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters)
        serviceRSAKey!.calculateKCV(rsaPrivateAsData)

        serviceRSAKCV = serviceRSAKey!.getKCV()
        serviceAESKCV = serviceAESKey!.getKCV()
        
        encryptedServicePrivateKey = serviceAESKey!.encrypt(rsaPrivateAsData, plainLength: rsaPrivateAsData!.count)
        
        /* Then the AES key under the device key */
        let aesKeyAsData = serviceAESKey!.getAsData()
        encryptedServiceAESKey = masterPassword.deviceRSAKey!.encrypt(aesKeyAsData, plainLength: (aesKeyAsData?.count)!)
        
        logger.log(.debug, message: "createServiceKeyWorker finalising");
        
        DispatchQueue.main.async(execute: {self.uploadServiceKey()} )

    }
    
    func loadServiceKey(_ json: NSDictionary) {
        
        if let keyStatus = json.object(forKey: "keyStatus") as? NSString {
            if keyStatus == "Available" {
                logger.log(.debug, message: "Service Key available")
                if let encryptedKeyValue = json.object(forKey: "encryptedKeyValue") as? NSString {
                    
                    if let keyKCV = json.object(forKey: "keyKCV") as? NSString {
                    
                        // Decrypt...
                        if let serviceKeyRaw = masterPassword.deviceRSAKey?.decrypt(encryptedKeyValue as String) {
                            let serviceKey = AESKey()
                            if serviceKey.loadKey(serviceKeyRaw) && serviceKey.checkKCV(keyKCV as String) {
                                logger.log(.debug, message: "ServiceKey loaded")
                                masterPassword.serviceKey = serviceKey
                                loadServiceKeyPair(json)
                                return;
                            }
                        }
                    }
                }
            }
            
            else if keyStatus == "None" {
                logger.log(.debug, message: "Service key not set - need to create one")
                /* Start a background threat to generate new keys */
                let createServiceWorkerThread = Thread(target: self, selector: #selector(AuthMeServiceInitialiser.createServiceKeyWorker), object: nil)
                createServiceWorkerThread.start()
                return
            }
        }
        
        logger.log(.debug, message: "Load of service key failed")
        
    }
    
    func loadServiceKeyPair(_ json: NSDictionary) {
        
        if let encryptedPrivateKey = json.object(forKey: "encryptedPrivateKey") as? NSString {
            if let publicKey = json.object(forKey: "publicKey") as? NSString {
                if let privateKCV = json.object(forKey: "privateKCV") as? NSString {
                
                    // Decrypt the private key
                    if let decryptedPrivateKey = masterPassword.serviceKey?.decrypt(encryptedPrivateKey as String, cipherLength: 0) {
                        let k = RSAKey(identifier: _AUTHME_SERVICE_RSA_KEY_TAG)
                        if (k?.loadPKCS8PrivateKey(decryptedPrivateKey as Data!))! &&
                            (k?.compareKCV(privateKCV as String))!
                        {
                            if (k?.loadPublicKey(publicKey as String))! {
                                masterPassword.serviceKeyPair = k
                                logger.log(.debug, message: "Service Key Pair loaded")
                                masterPassword.serviceActivated()
                                return
                            }
                        }
                    }
                }
                
            }
        }
        
        logger.log(.warn, message: "Failed to load service key pair")
        
    }
    
    func stateMachine(_ operation: AuthMeServiceOperation) {
        
        // This basically works through each of the steps to initialise
        
        switch operation.operationType {
            
        case .addDevice:
            logger.log(.debug, message: "Add Device Returned")
            if operation.statusCode == 200 || operation.statusCode == 201 {
                // Good to continue
                getDevice()
            }
            
        case .getDevice:
            logger.log(.debug, message: "Get Device Returned")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    let json = (try! JSONSerialization.jsonObject(with: readData as Data, options: JSONSerialization.ReadingOptions.mutableContainers)) as! NSDictionary
                    checkDevice(json, withNonce: operation.opaqueData as! String)
                }
            }
            
        case .getServiceKey:
            logger.log(.debug, message: "Get Service Key Returned")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    let json = (try! JSONSerialization.jsonObject(with: readData as Data, options: JSONSerialization.ReadingOptions.mutableContainers)) as! NSDictionary
                    loadServiceKey(json)
                }
            }
            
        case .setServiceKey:
            logger.log(.debug, message: "Set service key returned")
            if operation.statusCode == 201 {
                logger.log(.debug, message: "Service key created!")
                masterPassword.serviceKey = serviceAESKey
                masterPassword.serviceKeyPair = serviceRSAKey
                masterPassword.serviceActivated()
            }
            else {
                logger.log(.warn, message: "Set Service key failed - error \(operation.statusCode)")
            }
            
        default:
            logger.log(.error, message: "Unknown service operation returned!")
        }
    }
    
    func service(_ service: AuthMeService, didCompletOperation operation: AuthMeServiceOperation, withOpaqueData opaqueData: AnyObject?) {
        
        logger.log(.debug, message: "Service return")
        stateMachine(operation)
        
    }
    
    func signerDidComplete(_ signer: AuthMeSign, didSucceed: Bool, withOpaqueData opaqueData: AnyObject?) {
        logger.log(.debug, message: "Signer returned")
        
        _ = authme.setServiceKey(masterPassword.getUniqueDeviceId(),
            encryptedKeyValue: encryptedServiceAESKey,
            keyKCV: serviceAESKCV,
            encryptedPrivateKey: encryptedServicePrivateKey,
            privateKVC: serviceRSAKCV,
            publicKey: serviceRSAKey!.getPublicKey(),
            signature: signer, delegate: self)
        
    }
    
}

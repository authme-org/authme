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
//  MasterPassword.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 2/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation
import CoreData
import UIKit
import LocalAuthentication

// MARK: Callback protocol
protocol MasterPasswordCallback {
    
    func onServiceInitialised()
    func onServiceDeinitialised()
    
}


class MasterPassword : NSObject {
    
    let _AUTHME_DEVICE_RSA_KEY_TAG = "com.authme.iphone.new2"
    let _AUTHME_DEVICE_PASSWORD_TAG = "com.authme.iphone.password"
    let _AUTHME_RSA_KEY_LENGTH : Int32 = 256				/* Key size in bytes.  256 = 2048 bit key */
    let masterPasswordSalt : [UInt8] = [0x56, 0x14, 0x4f, 0x01, 0x5b, 0x8d, 0x44, 0x23] as [UInt8]
    let configCheckArray : [UInt8] = [0x6a, 0x6a, 0x6a] as [UInt8]



    enum PasswordState : Int {
        case open_STORE
        case create_PASS1
        case create_PASS2
    }
    
    let logger = Log()
    var managedObjectContext: NSManagedObjectContext? = nil
    var cachedConfig: Configuration?
    
    var passwordState = PasswordState.open_STORE
    var passwordFirstPass = ""
    var storePassword = ""
    var useTouchID = false
    
    var RSAGenAlert: UIAlertController? = nil
    
    var serviceActive = false
    var callbacks : [MasterPasswordCallback] = []
    
    // Keys
    var deviceRSAKey : RSAKey? = nil
    var storeKey : AESKey? = nil
    var serviceKey : AESKey? = nil
    var serviceKeyPair : RSAKey? = nil
    
    var authController: AuthListController? = nil
    
    override init() {
        logger.log(.debug, message: "Master Password initialising")
    }
    
    // MARK: Startup loading
    func requestStorePassword(_ prompt: String) {
        
        // Use an alert dialog to get password
        let alert = UIAlertController(title: "Master Password",
            message: prompt, preferredStyle: UIAlertControllerStyle.alert)
        alert.addAction(UIAlertAction(title: "OK", style: UIAlertActionStyle.default, handler: {(UIAlertAction) in
            self.passwordEntered((alert.textFields![0] as UITextField).text!)
        }))
        
        alert.addTextField(configurationHandler: {(textField: UITextField) in
            textField.placeholder = "Password"
        })
        UIApplication.shared.keyWindow!.rootViewController!.present(alert, animated: true, completion: nil)
    }
    
    
    func startup() {
        logger.log(.debug, message: "Master password commencing load")
        
        /* Open the master key data */
        
        // First load the Store Check Value so we can validate the password
        let request = NSFetchRequest<NSFetchRequestResult>()
        let entity = NSEntityDescription.entity(forEntityName: "Configuration", in: managedObjectContext!)
        request.entity = entity
        
        // Fetch
        var fetchResult : [AnyObject] = []
        
        do {
            fetchResult = try managedObjectContext!.fetch(request) as [AnyObject]!
        }
        catch _ {
        }
        
        /* Can we fetch the required class from the store? */
        if fetchResult.count == 0 {
            
            // Oh dear - need to create from scratch
            logger.log(.info, message: "Creating default configuration")
            cachedConfig = NSEntityDescription.insertNewObject(forEntityName: "Configuration", into: managedObjectContext!) as? Configuration
            do {
                try managedObjectContext?.save()
            } catch _ {
            }
        }
        else {
            cachedConfig = (fetchResult[0] as! Configuration)
        }
        
        // Load the configuration up
        AppConfiguration.getInstance().managedObjectContext = managedObjectContext
        
        // Find out if we have a TouchID that we want to enable
        let context = LAContext()
        let haveTouchId = context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: nil)
        
        // Now load the password
        if (cachedConfig!.checkString != nil) {
            passwordState = .open_STORE
            if haveTouchId && (cachedConfig!.useTouchID == NSNumber(value: 1 as Int32)) {
                requestTouchIDPassword()
            }
            else {
                requestStorePassword("Open Store - Enter Password")
            }
        }
        else {
            passwordState = .create_PASS1
            if haveTouchId {
                requestTouchIDSetup()
            }
            else {
                requestStorePassword("Initialise Store - Enter Password")
            }
        }
        
    }
    
    func requestTouchIDSetup() {
        
        // Use an alert dialog to ask the user whether to use TouchID
        let alert = UIAlertController(title: "Use Touch ID?",
            message: "Touch ID is active on this device.  Do you wish to use your fingerprint to secure this app?\n\nNOTE: You will still enter a password that can also be used in an emergency.",
            preferredStyle: UIAlertControllerStyle.alert)
        alert.addAction(UIAlertAction(title: "Yes", style: UIAlertActionStyle.default, handler: {(UIAlertAction) in

            self.useTouchID = true
            self.requestStorePassword("Initialise Store - Enter Password")
        }))

        alert.addAction(UIAlertAction(title: "No", style: UIAlertActionStyle.cancel, handler: {(UIAlertAction) in
            self.requestStorePassword("Initialise Store - Enter Password")
        }))

        UIApplication.shared.keyWindow!.rootViewController!.present(alert, animated: true, completion: nil)
        
    }
    
    func storePasswordToTouchID() {
        
        let keyChainStore = KeyChainPassword(identifier: _AUTHME_DEVICE_PASSWORD_TAG)
        
        keyChainStore?.setPassword(storePassword)
        if !(keyChainStore?.storeKey())! {
            logger.log(.warn, message: "Error storing password to keychain")
            useTouchID = false
        }
    }

    func requestTouchIDPassword() {
        
        let keyChainStore = KeyChainPassword(identifier: _AUTHME_DEVICE_PASSWORD_TAG)
        if (keyChainStore?.loadKey())! {
            storePassword = (keyChainStore?.getPassword())!
            logger.log(.debug, message: "Got Key: \(storePassword)")
            
            if !checkStore() {
                // We failed to get the correct password!
                // Invalidate current keys and reset
                //memset(key, 0, _AUTHME_ENCRYPT_KEY_LENGTH);
                storePassword = ""
                requestStorePassword("Touch ID failed to load - Enter Password")
                
                return
            }
            
            startInit()
        }
        else {
            logger.log(.warn, message: "Error loading password from Touch ID")
            requestStorePassword("Open Store - Enter Password")
        }
    }
    
    func passwordEntered(_ password: String) {
        
        logger.log(.finest, message: "Password = \(password)")
        
        // First of all - did someone type "RESET!" to get this to reset?
        if password == "RESET!" {
            logger.log(.debug, message: "User requested database reset")
            if let persistentStoreCoordinator = managedObjectContext?.persistentStoreCoordinator {
                
                // Do the shut down of the store
                var errorCode : NSError?
                if let store = persistentStoreCoordinator.persistentStores.last as NSPersistentStore? {
                    do {
                        try persistentStoreCoordinator.remove(store)
                        logger.log(.debug, message: "Store removed OK")
                    } catch let error as NSError {
                        errorCode = error
                        logger.log(.debug, message: "Store removal Error: \(errorCode), \(errorCode?.userInfo)");
                    }
            
                    // Now delete the file
                    // FIXME: dirty. If there are many stores...
                    // Delete file
                    if FileManager.default.fileExists(atPath: store.url!.path) {
                        do {
                            try FileManager.default.removeItem(atPath: store.url!.path)
                            logger.log(.debug, message:"Unresolved error \(errorCode), \(errorCode?.userInfo)")
                        } catch let error as NSError {
                            errorCode = error
                            logger.log(.debug, message: "Store file deleted OK")
                        }
                    }
                }
                
            }
            
            abort();
        }
        
        // Is this first entry or later?
        switch passwordState {

        case .create_PASS1:

            passwordFirstPass = password
                
            // Now load password screen again
            requestStorePassword("Initialise Store - Repeat Password")
            passwordState = .create_PASS2
            
            return
            
        case .create_PASS2:
        
            // This is second time entered - check and done!
            if passwordFirstPass == password {

                storePassword = password
                logger.log(.debug, message: "Initial entry of password succeeded")
                
                if useTouchID {
                    logger.log(.debug, message: "Storing password to keychain")
                    storePasswordToTouchID()
                }
                    
                // Use the password to build the 
                createStore()
                
                return
                
            }
            else {
                logger.log(.debug, message: "Initial entry of password failed")
                passwordFirstPass = ""
                passwordState = .create_PASS1
                requestStorePassword("Initialise Mismatch - Enter Password")
                
                return
            }
            
        case .open_STORE:
            
            storePassword = password
            
            // Now validate
            if !checkStore() {
                // We failed to get the correct password!
                // Invalidate current keys and reset
                //memset(key, 0, _AUTHME_ENCRYPT_KEY_LENGTH);
                storePassword = ""
                requestStorePassword("Incorrect Password - Enter Password")
                
                return
            }
            
        }
        
        startInit()

    }
    
    // MARK: Store management
    
    func createStoreWorker() {
    
        /* Used to generate the RSA key in the background and then switch back to the
         * main thread to close the alert window
        */
    
        logger.log(.debug, message:"rsaGEnThreadMain now generating keys")
    
        if deviceRSAKey != nil {
            deviceRSAKey!.destroy(true)
            deviceRSAKey = nil;
        }
    
        deviceRSAKey = RSAKey(identifier: _AUTHME_DEVICE_RSA_KEY_TAG)
        if !deviceRSAKey!.generate(_AUTHME_RSA_KEY_LENGTH * 8) {
            logger.log(.warn, message: "Error generating RSA key");
            return;
        }
    
        logger.log(.debug, message: "ceateStoreWorker creating configuration");
        
        /* Create the AES wrapper using the password */
        let pwKey = AESKey()
        pwKey.setKeyFromPassword(storePassword, withSalt: Data(bytes: UnsafePointer<UInt8>(masterPasswordSalt), count: 8), ofLength: 8)
        
        /* Create the store key */
        storeKey = AESKey()
        if !storeKey!.generateKey() {
            logger.log(.warn, message: "Error generating store key")
            return
        }
        
        /* Encrypt the check value, RSA Key pair and the store key to save */
        let encodedCheckValue = storeKey!.encrypt(Data(bytes: UnsafePointer<UInt8>(configCheckArray), count: 3), plainLength: 3)
        let rawStoreKey = Data(bytes: UnsafePointer<UInt8>(storeKey!.key), count: 32)
        let encryptedStoreKey = pwKey.encrypt(rawStoreKey, plainLength: 32)
        let rawPublicKey = deviceRSAKey?.getPublicKey()
        let rawPrivateKey = deviceRSAKey?.getPrivateKey()
        let encryptedPrivateKey = storeKey!.encrypt(rawPrivateKey)
        let checkStringRSA = deviceRSAKey?.encrypt(Data(bytes: UnsafePointer<UInt8>(configCheckArray), count: 3), plainLength: 3)
        
        // Take the encoded result and store
    
        cachedConfig!.checkString = encodedCheckValue
        cachedConfig!.nextId = NSNumber(value: 1 as Int32)
        cachedConfig!.storeKey = encryptedStoreKey
        cachedConfig!.deviceKeyPrivate = encryptedPrivateKey
        cachedConfig!.deviceKeyPublic = rawPublicKey
        cachedConfig!.checkStringRSA = checkStringRSA
        cachedConfig!.useTouchID = NSNumber(value: useTouchID ? 1 : 0 as Int32)
        cachedConfig!.deviceUUID = UIDevice.current.identifierForVendor!.uuidString
    
        do {
            try managedObjectContext!.save()
        } catch _ {
            
            logger.log(.error, message:"Problem saving the configuration")
            abort();
        }
    
        logger.log(.debug, message: "createStoreWorker finalising");
        
        UIApplication.shared.keyWindow!.rootViewController!.dismiss(animated: true, completion: nil)
        
        DispatchQueue.main.async(execute: {self.startInit()} )
        
    }
    
    func startInit() {
        
        // Only get here if things are OK
        let settings = UIUserNotificationSettings(types: [.alert, .sound, .badge], categories: nil)
        UIApplication.shared.registerUserNotificationSettings(settings)        
        UIApplication.shared.registerForRemoteNotifications()

        let initialiser = AuthMeServiceInitialiser()
        initialiser.doInit()
    }

    func createStore() {
    
    
        /* This takes a lot of CPU so we put up a message with and delay the work
         * while it goes up */
    
        //[self performSelector:@selector(createStoreWorker) withObject:nil afterDelay:.5];
    
        logger.log(.debug, message: "Starting RSA")
        RSAGenAlert = UIAlertController(title: "Generating Key",
            message: "Generating RSA Key\nPlease wait...", preferredStyle: UIAlertControllerStyle.alert)

        let alertFrame = RSAGenAlert!.view.frame
        let activityIndicator = UIActivityIndicatorView(activityIndicatorStyle: UIActivityIndicatorViewStyle.whiteLarge)
        
        activityIndicator.frame = CGRect(x: 125,y: alertFrame.size.height+115, width: 30,height: 30);
        activityIndicator.isHidden = false;
        activityIndicator.contentMode = UIViewContentMode.center
        activityIndicator.startAnimating()
        RSAGenAlert!.view.addSubview(activityIndicator)
        UIApplication.shared.keyWindow!.rootViewController!.present(RSAGenAlert!, animated: true, completion: nil)
        
        let createStoreWorkerThread = Thread(target: self, selector: #selector(MasterPassword.createStoreWorker), object: nil)
        createStoreWorkerThread.start()
    }
    
    func checkStore() -> Bool {
        
        /* Know we have all the basic store values - need to validate them using the entered password */
        let pwKey = AESKey()
        pwKey.setKeyFromPassword(storePassword, withSalt: Data(bytes: UnsafePointer<UInt8>(masterPasswordSalt), count: 8), ofLength: 8)

        /* Can we load the store key? */
        if let decryptedStoreKey = pwKey.decrypt(cachedConfig!.storeKey!, cipherLength: 0) {
            // Decrypt worked for store Key
            storeKey = AESKey()
            if storeKey!.loadKey(decryptedStoreKey as Data!) {
                // Key loaded OK - check the check value
                if let decryptedCheckValue = storeKey?.decrypt(cachedConfig!.checkString!, cipherLength: 0) {
                    var good = true
                    let checkBytes = decryptedCheckValue.bytes.bindMemory(to: UInt8.self, capacity: decryptedCheckValue.length)
                    for i in 0..<configCheckArray.count {
                        if configCheckArray[i] != checkBytes[i] {
                            good = false
                        }
                    }
                    if good {
                        // Load the RSA Key
                        logger.log(.debug, message:"Loading RSA ley")
                        
                        if deviceRSAKey != nil {
                            deviceRSAKey!.destroy(true)
                            deviceRSAKey = nil;
                        }
                        
                        deviceRSAKey = RSAKey(identifier: _AUTHME_DEVICE_RSA_KEY_TAG)
                        
                        // This is an internal test - we don't want the keys persisting
                        // in the keychain
                        
                        if deviceRSAKey!.loadKeysFromKeychain() {
                            // Want to make sure this *NEVER* happens
                            logger.log(.error, message: "Error KEY FOUND IN KEY CHAIN");
                            abort();
                            //return false
                        }
                        
                        // Now do decrypts against check values and then do an
                        // encrypt/decrypt to see it works
                        good = false
                        if let decryptedPrivateKey = storeKey?.decrypt(cachedConfig!.deviceKeyPrivate!, cipherLength: 0) {
                            if deviceRSAKey!.loadPrivateKey(NSString(data: decryptedPrivateKey as Data, encoding: String.Encoding.utf8.rawValue) as! String) {
                                if deviceRSAKey!.loadPublicKey(cachedConfig!.deviceKeyPublic) {
                                    logger.log(.debug, message: "RSA Key loaded")
                                    
                                    // Quick internal tests
                                    if let decRSACheck = deviceRSAKey?.decrypt(cachedConfig!.checkStringRSA) {
                                        let decRSACheckBytes = (decRSACheck as NSData).bytes.bindMemory(to: UInt8.self, capacity: decRSACheck.count)

                                        let encTest = deviceRSAKey?.encrypt(Data(bytes: UnsafePointer<UInt8>(configCheckArray), count: 3), plainLength: 3)
                                        if let decTest = deviceRSAKey?.decrypt(encTest) {
                                            let decTestBytes = (decTest as NSData).bytes.bindMemory(to: UInt8.self, capacity: decTest.count)
                                            good = true
                                            for i in 0..<configCheckArray.count {
                                                if (configCheckArray[i] != checkBytes[i]) ||
                                                    (configCheckArray[i] != decRSACheckBytes[i]) ||
                                                    (configCheckArray[i] != decTestBytes[i]) {
                                                    good = false
                                                }
                                            }
                                        }
                                        else {
                                            good = false
                                        }
                                    }

                                }
                            }
                            
                        }
                        
                        if !good {
                            logger.log(.debug, message: "RSA Test failed")
                        }
                        else {
                            logger.log(.debug, message: "All RSA tests passed")
                            return true
                        }
                    }
                }
                
            }
        }
        
        return false
        
    }
    
    // MARK: Secret wrapping / unwrapping
    
    /*
    * A secret is made up of a Base64 encoded byte array
    * bytes 1-4 is the length of the encrypted AES key (LEN)
    * bytes 5-(5+LEN) is the AES key encrypted in the service public key
    * bytes (5+LEN) - (5+LEN+16) is the AES IV - 16 BYTES
    * bytes (5+LEN+16) - (END) is the secret we are actually unwrapping encrypted with teh AES key
    */

    func unwrapSecret(_ wrappedSecret: String) -> String? {
        
        /* Sanity checks */
        if (wrappedSecret == "" || serviceKeyPair == nil) {
            return nil
        }
        
        /* Have to decode first */
        let wrappedLength = wrappedSecret.characters.count
        if let rawSecret = Base64().base64decode(wrappedSecret, length: Int32(wrappedLength)) {
            let rawBytes = UnsafeMutablePointer<UInt8>(mutating: rawSecret.bytes.bindMemory(to: UInt8.self, capacity: rawSecret.length))
            // Size of WrapBufLen
            var wrapBufLen = 0
            for i in 0..<4 {
                wrapBufLen = wrapBufLen << 8
                let orVal = rawBytes[i]
                wrapBufLen = wrapBufLen | Int(orVal)
            }
            
            /* Create the right NSData so we can decrypt using private key */
            let wrapBufBytes = UnsafeMutableRawPointer(rawBytes.advanced(by: 4))
            if let aesKey = serviceKeyPair?.decryptData(Data(bytesNoCopy: wrapBufBytes, count: wrapBufLen, deallocator: .none)) {
                logger.log(.finest, message: "Public key decrypt in unwrap worked");
                
                /* Now get the last part of the buffer */
                let aesBytes = UnsafeMutableRawPointer(rawBytes.advanced(by: 4 + wrapBufLen))
                let aes = AESKey()
                if aes.loadKey(aesKey) {
                    if let decrypt = aes.decryptData(Data(bytesNoCopy: aesBytes, count: rawSecret.length - 4 - wrapBufLen, deallocator: .none)) {
                        logger.log(.finest, message: "AES decrypt in unwrap worked");
                        let ret = Base64().base64encode(decrypt as Data, length: Int32(decrypt.length))
                        return String(describing: ret)
                    }
                }
            }
        }
        
        return nil
        
    }
    
    // MARK: Helper functions
    func getUniqueDeviceId() -> String {
        if cachedConfig?.deviceUUID != nil {
            return cachedConfig!.deviceUUID!
        }
        
        // This is a fail safe - not a good idea as this can change
        return UIDevice.current.identifierForVendor!.uuidString
    }
    
    func getDeviceName() -> String {
        return UIDevice.current.name
    }
    
    // MARK: Service handling
    func checkServiceActive(_ callback: MasterPasswordCallback?, registerCallback: Bool) -> Bool {
        
        if registerCallback && callback != nil {
            callbacks.append(callback!)
        }
        
        return serviceActive
        
    }
    
    // Called by the service initialiser when done
    func serviceActivated() {
        
        logger.log(.debug, message: "Service activation completed successfully - starting callbacks")
        serviceActive = true
        
        for i in callbacks {
            i.onServiceInitialised()
        }
    }
    
    // If username/password changes
    func serviceDeactivated() {
        
        if serviceActive {
            logger.log(.debug, message: "Service activation reversed - destroying service details")
            serviceActive = false
        
            /* Destroy keys */
            serviceKey = nil
            if serviceKeyPair != nil {
                /* Remove key from key chain as well as deleting our copy */
                serviceKeyPair?.destroy(true)
                serviceKeyPair = nil
            }
            
            /* Tell anyone using service info we're out for the count */
            for i in callbacks {
                i.onServiceDeinitialised()
            }
        }
    }
    
    // MARK: TouchID KeyChain handling

    
    // MARK: Singleton Handling
    class func getInstance() -> MasterPassword {
        return sharedInstance
    }
    
    class var sharedInstance: MasterPassword {
        struct Static {
            static let instance: MasterPassword = MasterPassword()
        }
        return Static.instance
    }
    
}

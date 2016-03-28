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
//  DeviceListController.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 31/01/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

import Foundation

import UIKit

class DeviceListController: UITableViewController, MasterPasswordCallback, AuthMeServiceDelegate, AuthMeSignDelegate {
    
    var logger = Log()
    
    var masterPasswordStarted = false
    var serviceInitialised = false
    var masterPassword : MasterPassword? = nil
    var devices : [DeviceInfo] = []
    var authMe = AuthMeService()
    
    override func viewDidAppear(animated: Bool) {
        
        super.viewDidAppear(animated)
        
    }
    
    override func viewDidLoad() {
        
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        let reloadImage = UIImage(named: "AuthMe-Nav-Reload.png")
        let reloadButton = UIBarButtonItem(image: reloadImage, style: UIBarButtonItemStyle.Plain, target: self, action: #selector(DeviceListController.reloadDevices))
        let actionItems = [reloadButton]
        
        self.navigationItem.rightBarButtonItems = actionItems
        
        // Setup for device list management
        masterPassword = MasterPassword.getInstance()
        
        // Check if service activation has completed.  It shouldn't have -
        // so we also register for a callback when it does
        if masterPassword!.checkServiceActive(self, registerCallback: true) {
            serviceInitialised = true
            reloadDevices()
        }
        
    }
    
    // MARK: TableView implementation
    override func numberOfSectionsInTableView(tableView: UITableView) -> Int {
        return 1
    }
    
    override func tableView(tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return "Registered Devices"
    }
    
    override func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return devices.count
    }
    
    
    // Auth has been selected
    override func tableView(tableView: UITableView, didSelectRowAtIndexPath indexPath: NSIndexPath) {
        
        /* Sanity checks */
        if indexPath.section != 0 || indexPath.row < 0 || indexPath.row >= devices.count {
            logger.log(.ERROR, message: "Recieved a stupid index path entry")
            return
        }
        
        let device = devices[indexPath.row]
        
        logger.log(.FINE, message: "didSelectRowAtIndexPath for \(device.deviceUniqueId)")
        
        /* Create an alert controller to ask user if this is OK to approve */
        let alert = UIAlertController(title: "Approve Device",
            message: "Register this device?", preferredStyle: UIAlertControllerStyle.Alert)
        alert.addAction(UIAlertAction(title: "Yes", style: UIAlertActionStyle.Default, handler: {(UIAlertAction) in
            self.approve(device)
        }))
        alert.addAction(UIAlertAction(title: "Cancel", style: UIAlertActionStyle.Cancel, handler: nil))
        
        UIApplication.sharedApplication().keyWindow!.rootViewController!.presentViewController(alert, animated: true, completion: nil)
        
        self.tableView.deselectRowAtIndexPath(indexPath, animated: true)
        
    }
    
    override func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        
        let cell = tableView.dequeueReusableCellWithIdentifier("DeviceCell", forIndexPath: indexPath)
        
        let device = devices[indexPath.row]
        
        // Get the labels we need to fill in
        let deviceName = cell.viewWithTag(3001) as? UILabel
        let deviceId = cell.viewWithTag(3002) as? UILabel
        let deviceRegistered = cell.viewWithTag(3003) as? UILabel
        
        deviceName?.text = device.name
        deviceId?.text = device.deviceUniqueId
        if device.serviceKeyStatus == "Loaded" {
            deviceRegistered?.text = "YES"
        }
        else {
            deviceRegistered?.text = "NO"
        }
        
        return cell
    }
    
    override func tableView(tableView: UITableView, canEditRowAtIndexPath indexPath: NSIndexPath) -> Bool {
        // Return false if you do not want the specified item to be editable.
        return true
    }
    
    // MARK: MasterPassword callbacks
    func onServiceInitialised() {
        serviceInitialised = true
        reloadDevices()
    }
    
    func onServiceDeinitialised() {
        serviceInitialised = false
        devices = []
        self.tableView.reloadData()
    }
    
    // MARK: Service Callback
    func service(service: AuthMeService, didCompletOperation operation: AuthMeServiceOperation, withOpaqueData opaqueData: AnyObject?) {
        
        // This basically works through each of the steps to initialise
        
        switch operation.operationType {
            
        case .GetDevices:
            logger.log(.DEBUG, message: "Service callback for GetDevices")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    if let json = (try? NSJSONSerialization.JSONObjectWithData(readData, options: NSJSONReadingOptions.MutableContainers)) as? NSDictionary {
                        if let jsonDeviceList = json.objectForKey("devices") as? NSArray {
                            
                            // Alll existing authchecks are erased
                            devices = []
                            for i in jsonDeviceList {
                                if let j = i as? NSDictionary {
                                    let device = DeviceInfo(json: j)
                                    devices.append(device)
                                }
                            }
                            // REload the table view
                            self.tableView.reloadData()
                        }
                    }
                    
                }
            }
            
        case .SetServiceKey:
            logger.log(.DEBUG, message: "Service callback for SetServiceKey")
            
            if operation.statusCode != 201 {
                logger.log(.WARN, message: "Upload of device service key failed")
            }
            
            self.reloadDevices()
                
        default:
            logger.log(.ERROR, message: "Unknown service operation returned!")
        }
    }
    
    // AuthList service interaction
    func reloadDevices() {
        
        if !serviceInitialised {
            return
        }
        
        logger.log(.FINE, message: "reloading devices")
        authMe.getDevices(self)
        
    }
    
    func approve(device: DeviceInfo) {
        
        /* Authorise this device with the service */
        let deviceKey = RSAKey()
        deviceKey.loadPublicKey(device.publicKey)
        
        /* Encrypt the service key using the device public key */
        if let aesKey = masterPassword?.serviceKey?.getKeyAsData() {
            let encryptedServiceKey = deviceKey.encrypt(aesKey, plainLength: aesKey.length)
            device.encryptedData = encryptedServiceKey
            
            /* sign */
            let signature = AuthMeSign()
            signature.doSign(device.deviceUniqueId + masterPassword!.serviceKey!.getKCV() + encryptedServiceKey,
                keyPair: masterPassword!.deviceRSAKey!, delegate: self, withOpaqueData: device)
            
        }
    }
    
    // AuthMeSign delegate return
    func signerDidComplete(signer: AuthMeSign, didSucceed: Bool, withOpaqueData opaqueData: AnyObject?) {
        logger.log(.FINEST, message: "AuthMeSign returned to controller")
        
        if let di = opaqueData as? DeviceInfo {
            
            // Was a device authorise request
            
            authMe.setServiceKey(di.deviceUniqueId, encryptedKeyValue: di.encryptedData, keyKCV: masterPassword!.serviceKey!.getKCV(), encryptedPrivateKey: "", privateKVC: "", publicKey: "", signature: signer, delegate: self)
            
        }
    }
}
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
//  AuthListController.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 2/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation
import UIKit

class AuthListController: UITableViewController, MasterPasswordCallback, AuthMeServiceDelegate, AuthMeSignDelegate {
    
    var logger = Log()
    
    var masterPasswordStarted = false
    var serviceInitialised = false
    var masterPassword : MasterPassword? = nil
    var authChecks : [SvcSession] = []
    var authMe = AuthMeService()
    
    override func viewDidAppear(animated: Bool) {
        
        super.viewDidAppear(animated)

        if !masterPasswordStarted {
            masterPassword = MasterPassword.getInstance()
            masterPassword!.authController = self
            masterPassword!.startup()
            masterPasswordStarted = true
        }
    }
    
    override func viewDidLoad() {
        
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        let reloadImage = UIImage(named: "AuthMe-Nav-Reload.png")
        let reloadButton = UIBarButtonItem(image: reloadImage, style: UIBarButtonItemStyle.Plain, target: self, action: #selector(AuthListController.reloadAuths))
        let actionItems = [reloadButton]
        
        self.navigationItem.rightBarButtonItems = actionItems
        
        // Setup for auth list management
        masterPassword = MasterPassword.getInstance()
        
        // Check if service activation has completed.  It shouldn't have - 
        // so we also register for a callback when it does
        if masterPassword!.checkServiceActive(self, registerCallback: true) {
            reloadAuths()
        }
        
    }
    
    // MARK: TableView implementation
    override func numberOfSectionsInTableView(tableView: UITableView) -> Int {
        return 1
    }
    
    override func tableView(tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return "Waiting Auth Checks"
    }
    
    override func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return authChecks.count
    }
    
    
    // Auth has been selected
    override func tableView(tableView: UITableView, didSelectRowAtIndexPath indexPath: NSIndexPath) {
        
        /* Sanity checks */
        if indexPath.section != 0 || indexPath.row < 0 || indexPath.row >= authChecks.count {
            logger.log(.ERROR, message: "Recieved a stupid index path entry")
            return
        }
        
        let svcSession = authChecks[indexPath.row]
        
        logger.log(.FINE, message: "didSelectRowAtIndexPath for \(svcSession.checkId)")
        
        /* Create an alert controller to ask user if this is OK to approve */
        let alert = UIAlertController(title: "Approve Authorisation",
            message: "Please approve or deny this action", preferredStyle: UIAlertControllerStyle.Alert)
        alert.addAction(UIAlertAction(title: "Approve", style: UIAlertActionStyle.Default, handler: {(UIAlertAction) in
            self.approve(svcSession)
        }))
        alert.addAction(UIAlertAction(title: "Deny", style: UIAlertActionStyle.Default, handler: {(UIAlertAction) in
            self.deny(svcSession)
        }))
        alert.addAction(UIAlertAction(title: "Cancel", style: UIAlertActionStyle.Cancel, handler: nil))
        
        UIApplication.sharedApplication().keyWindow!.rootViewController!.presentViewController(alert, animated: true, completion: nil)
        
        self.tableView.deselectRowAtIndexPath(indexPath, animated: true)
    }
    
    override func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        
        let cell = tableView.dequeueReusableCellWithIdentifier("AuthCell", forIndexPath: indexPath) 
        
        let auth = authChecks[indexPath.row]
        
        // Get the labels we need to fill in
        let serverLabel = cell.viewWithTag(1001) as? UILabel
        let msgLabel = cell.viewWithTag(1002) as? UILabel
        let timeLabel = cell.viewWithTag(1003) as? UILabel
        
        /* Sort out an appropriate time label */
        
        let sd = auth.serverNSDate
        var ti = sd.timeIntervalSinceNow

        if (ti < 0) {
            ti *= -1.0
        }
        
        logger.log(.FINEST, message: "TimeInterval = \(ti)")
        
        /* 86400 = number of seconds in a day */
        let df = NSDateFormatter()

        if (ti > 86400.0) {
            df.dateFormat = "MM/dd/yy"
        }
        else {
            df.dateFormat = "h:mm a"
        }
        
        logger.log(.FINEST, message: "Incoming date: \(auth.serverDate) Outgoing Date \(df.stringFromDate(sd))")
        
        serverLabel?.text = auth.serverId
        msgLabel?.text = auth.serverString
        timeLabel?.text = df.stringFromDate(sd)
        
        return cell
    }
    
    override func tableView(tableView: UITableView, canEditRowAtIndexPath indexPath: NSIndexPath) -> Bool {
        // Return false if you do not want the specified item to be editable.
        return true
    }
    
    // MARK: MasterPassword callbacks
    func onServiceInitialised() {
        serviceInitialised = true
        reloadAuths()
    }
    
    func onServiceDeinitialised() {
        serviceInitialised = false
        authChecks = []
        self.tableView.reloadData()
    }
    
    // MARK: Service Callback
    func service(service: AuthMeService, didCompletOperation operation: AuthMeServiceOperation, withOpaqueData opaqueData: AnyObject?) {
        
        // This basically works through each of the steps to initialise
        
        switch operation.operationType {
            
        case .GetAuthChecks:
            logger.log(.DEBUG, message: "Service callback for GetAuthChecks")
            if operation.statusCode == 200 {
                if let readData = operation.returnData {
                    if let json = (try? NSJSONSerialization.JSONObjectWithData(readData, options: NSJSONReadingOptions.MutableContainers)) as? NSDictionary {
                        if let jsonAuthList = json.objectForKey("authChecks") as? NSArray {
                            
                            // Alll existing authchecks are erased
                            authChecks = []
                            for i in jsonAuthList {
                                if let j = i as? NSDictionary {
                                    let svcSession = SvcSession(json: j)
                                    authChecks.append(svcSession)
                                }
                            }
                            // REload the table view
                            authChecks.sortInPlace({$0.serverNSDate.timeIntervalSinceNow > $1.serverNSDate.timeIntervalSinceNow})
                            self.tableView.reloadData()
                        }
                    }
                    
                }
            }
            
        case .SetAuthCheckStatus:
            logger.log(.DEBUG, message: "Service callback for setauthcheckstatus")
            
            /* Did it success or fail? */
            var message = ""
            var title = ""
            if operation.statusCode == 400 {
                title = "Failed"
                message = "Has this check already been actioned?"
            }
            else if operation.statusCode == 200 {
                title = "Success"
                message = "Update to status succeeded"
            }
            else {
                title = "Failed"
                message = "Update operation failed"
            }
            
            let alert = UIAlertController(title: title,
                message: message, preferredStyle: UIAlertControllerStyle.Alert)
            alert.addAction(UIAlertAction(title: "Close", style: UIAlertActionStyle.Default, handler: nil))
            
            let rootController = UIApplication.sharedApplication().keyWindow!.rootViewController!
            
            // Dismiss current alert and tell the user what happened
            
            rootController.dismissViewControllerAnimated(true, completion: {
                rootController.presentViewController(alert, animated: true, completion: nil)
            })
            
        default:
            logger.log(.ERROR, message: "Unknown service operation returned!")
        }
    }
    
    // AuthList service interaction
    func reloadAuths() {

        if !serviceInitialised {
            return
        }
        
        logger.log(.FINE, message: "reloading auths")
        authMe.getAuthChecks(self)
        
    }
    
    func setAuthCheckStatus(svcSession: SvcSession, status: String) {
        let signer = AuthMeSign()
        svcSession.status = status
        
        let alert = UIAlertController(title: "Setting Status",
            message: "Setting check to \(status)", preferredStyle: UIAlertControllerStyle.Alert)        
        UIApplication.sharedApplication().keyWindow!.rootViewController!.presentViewController(alert, animated: true, completion: nil)
        signer.doSign("\(svcSession.checkId)\(svcSession.serverNonce)\(status)\(svcSession.unwrappedSecret)", keyPair: masterPassword!.serviceKeyPair!, delegate: self, withOpaqueData: svcSession)
    }
    
    func approve(svcSession: SvcSession) {
        logger.log(.FINE, message: "Approving \(svcSession.checkId)")
        
        /* First of all see if we need to unwrap something */
        if (svcSession.wrappedSecret != "") {
            logger.log(.FINEST, message: "Have a secret to unwrap")
            if let unwrappedSecret = masterPassword?.unwrapSecret(svcSession.wrappedSecret) {
                svcSession.unwrappedSecret = unwrappedSecret
            }
        }
        
        setAuthCheckStatus(svcSession, status: "APPROVED")
    }

    func deny(svcSession: SvcSession) {
        logger.log(.FINE, message: "Denying \(svcSession.checkId)")
        setAuthCheckStatus(svcSession, status: "DECLINED")
    }
    
    // AuthMeSign delegate return
    func signerDidComplete(signer: AuthMeSign, didSucceed: Bool, withOpaqueData opaqueData: AnyObject?) {
        logger.log(.FINEST, message: "AuthMeSign returned to controller")
        
        if let ss = opaqueData as? SvcSession {
            
            // Was a authorise or deauthorise request
            authMe.setAuthCheckStatus(ss, withStatus: ss.status, withSignature: signer, withUnwrappedSecret: ss.unwrappedSecret, delegate: self)
            
        }
    }
}
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
//  ConfigurationDetailMenuController.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 6/09/2014.
//  Copyright (c) 2014 Berin Lautenbach. All rights reserved.
//

import UIKit
import Foundation

class ConfigurationDetailMenuController: UITableViewController, UITextFieldDelegate {
    
    var logger = Log()
 
    // Passed in by the Master controller to tell us what to load
    var configTemplate: NSArray? = nil
    
    // Used to hold fields being edited
    var editFields: NSMutableDictionary? = nil
    var currentTextField: UITextField? = nil
    
    var didEdit = false
    
    // For when we check service config details
    var visibleAlert: UIAlertController? = nil
    
    var keyChainServiceHolder = ""
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        // Do we need a save button?
        for var i = 0; i <  configTemplate?.count ; i += 1 {
            
            let dict = configTemplate?.objectAtIndex(i) as! NSDictionary
            if let sectionConfig = dict.objectForKey("ConfigurationItems") as? NSArray {
                
                for j in 0 ..< sectionConfig.count {
                    
                    if let config = sectionConfig.objectAtIndex(j) as? NSDictionary {
                        if  (config.objectForKey("DBClass") != nil && config.objectForKey("DBClass") as? String == "String") ||
                            config.objectForKey("InputType") != nil ||
                            config.objectForKey("KeyChainService") != nil {
                        
                                let saveButton = UIBarButtonItem(barButtonSystemItem: .Save, target: self, action: #selector(ConfigurationDetailMenuController.save(_:)))
                                self.navigationItem.rightBarButtonItem = saveButton
                                if editFields == nil {
                                    editFields = NSMutableDictionary()
                                }
                                didEdit = false
                                return
                        }
                    }
                }
            }
        }
        
    }
    
    override func viewWillDisappear(animated: Bool) {
        if didEdit {
            logger.log(.DEBUG, message: "User navigated away without saving changes")
            let alert = UIAlertController(title: "Save Changes?",
                message: "You have not saved your changes - do you want to do so?",
                preferredStyle: UIAlertControllerStyle.Alert)
            
            alert.addAction(UIAlertAction(title: "Yes", style: UIAlertActionStyle.Default, handler: { action in
                self.save(self)
                
            }))
            alert.addAction(UIAlertAction(title: "No", style: UIAlertActionStyle.Cancel, handler: nil))
            self.presentViewController(alert, animated:true, completion: nil)
        }
    }
    
    override func viewWillAppear(animated: Bool) {
        
        // If we were swapped out - reload
        
        //editFields = NSMutableDictionary()
        self.tableView.reloadData()
        //if let visibleCells = self.tableView.indexPathsForVisibleRows() {
        //  self.tableView.reloadRowsAtIndexPaths(visibleCells, withRowAnimation: UITableViewRowAnimation.Automatic)
        //}
        
    }
    
    
    override func willAnimateRotationToInterfaceOrientation(toInterfaceOrientation: UIInterfaceOrientation, duration: NSTimeInterval) {

        if let visibleCells = self.tableView.indexPathsForVisibleRows {
            self.tableView.reloadRowsAtIndexPaths(visibleCells, withRowAnimation: UITableViewRowAnimation.Automatic)
        }
    }

    
    // MARK: Cell Handling
    override func tableView(tableView: UITableView, willDisplayCell cell: UITableViewCell, forRowAtIndexPath indexPath: NSIndexPath) {
        
        /* Give us a nice "configuration look" cell.  Taken from a 
         * stackoverflow.com answer and converted to swift.
         * See: http://stackoverflow.com/questions/18822619/ios-7-tableview-like-in-settings-app-on-ipad
        */
        
        if cell.respondsToSelector(Selector("tintColor")) {
            if tableView == self.tableView {
                
                /* This is us! */
                let cornerRadius: CGFloat  = 5
                cell.backgroundColor = UIColor.clearColor()
                let layer = CAShapeLayer()
                let pathRef = CGPathCreateMutable()
                let bounds = CGRectInset(cell.bounds, 10, 0)
                let tableBounds = tableView.bounds
                logger.log(.DEBUG, message: "cell width = \(cell.bounds.width) table width = \(tableBounds.width) view width = \(self.view.bounds.width)")
                //var bounds = CGRectInset(cell.frame, 10, 0)
                
                var addLine = false
                
                /* Case of a singleton cell? */
                if indexPath.row == 0 && indexPath.row == tableView.numberOfRowsInSection(indexPath.section) - 1 {
                    CGPathAddRoundedRect(pathRef, nil, bounds, cornerRadius, cornerRadius)
                }
                
                /* Top cell of a multi cell group */
                else if indexPath.row == 0 {
                    CGPathMoveToPoint(pathRef, nil, CGRectGetMinX(bounds), CGRectGetMaxY(bounds))
                    CGPathAddArcToPoint(pathRef, nil, CGRectGetMinX(bounds), CGRectGetMinY(bounds), CGRectGetMidX(bounds), CGRectGetMinY(bounds), cornerRadius)
                    CGPathAddArcToPoint(pathRef, nil, CGRectGetMaxX(bounds), CGRectGetMinY(bounds), CGRectGetMaxX(bounds), CGRectGetMidY(bounds), cornerRadius);
                    CGPathAddLineToPoint(pathRef, nil, CGRectGetMaxX(bounds), CGRectGetMaxY(bounds));
                    addLine = true;
                }
                    
                /* Bottom cell of a multi cell group */
                else if indexPath.row == (tableView.numberOfRowsInSection(indexPath.section) - 1) {
                    
                    CGPathMoveToPoint(pathRef, nil, CGRectGetMinX(bounds), CGRectGetMinY(bounds))
                    CGPathAddArcToPoint(pathRef, nil, CGRectGetMinX(bounds), CGRectGetMaxY(bounds), CGRectGetMidX(bounds), CGRectGetMaxY(bounds), cornerRadius)
                    CGPathAddArcToPoint(pathRef, nil, CGRectGetMaxX(bounds), CGRectGetMaxY(bounds), CGRectGetMaxX(bounds), CGRectGetMidY(bounds), cornerRadius)
                    CGPathAddLineToPoint(pathRef, nil, CGRectGetMaxX(bounds), CGRectGetMinY(bounds))
                }
                
                else {
                    CGPathAddRect(pathRef, nil, bounds);
                    addLine = true;
                }
                
                /* Now plot it */
                layer.path = pathRef
                //CFRelease(pathRef) - not required - automatically released now
                layer.fillColor = UIColor(white: 1.0, alpha: 0.8).CGColor
                
                if addLine {
                    let lineLayer = CALayer()
                    let lineHeight = 1.0 / UIScreen.mainScreen().scale
                    lineLayer.frame = CGRectMake(CGRectGetMinX(bounds)+10, bounds.size.height-lineHeight, bounds.size.width-10, lineHeight)
                    lineLayer.backgroundColor = tableView.separatorColor!.CGColor;
                    layer.addSublayer(lineLayer)
                }
                
                /* Now add it! */
                let toAdd = UIView(frame: bounds)
                toAdd.layer.insertSublayer(layer, atIndex: 0)
                toAdd.backgroundColor = UIColor.clearColor()
                cell.backgroundView = toAdd
                
                /* Now for when selected */
                let bgLayer = CAShapeLayer()
                bgLayer.path = pathRef
                bgLayer.fillColor = UIColor(red: (76.0/255), green: (161.0/255.0), blue: 1.0, alpha: 1.0).CGColor
                
                let bgColourView = UIView(frame: bounds)
                bgColourView.layer.insertSublayer(bgLayer, atIndex: 0)
                bgColourView.layer.masksToBounds = true;
                cell.selectedBackgroundView = bgColourView;

                
            }
        }
        
    }
    
    // Customize the appearance of table view cells.
    override func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        
        logger.log(.FINE, message: "At start of cellForRowAtIndexPath")
        
        /* Load the specific configuration section for where we are */
        var _config: NSDictionary? = nil
        
        if let dict = configTemplate?.objectAtIndex(indexPath.section) as? NSDictionary {
            if let array = dict.objectForKey("ConfigurationItems") as? NSArray {
                _config = array.objectAtIndex(indexPath.row) as? NSDictionary
            }
        }
        
        if _config == nil {
            logger.log(.ERROR, message: "Error loading configTemplate")
            return UITableViewCell()
        }
        
        let config = _config! as NSDictionary
        let appConfiguration = AppConfiguration.getInstance()
        
        /* What kind of cell should we load? */
        if  (config.objectForKey("DBClass") != nil && config.objectForKey("DBClass") as? String == "String") ||
            (config.objectForKey("ConfigClass") != nil && config.objectForKey("ConfigClass") as? String == "String") ||
            config.objectForKey("InputType") != nil ||
            config.objectForKey("Password") != nil {
            
            // Something we're going to save in a database
            let LEFT_LABEL_TAG = 2001
            let EDIT_TAG = 2002
            let cellIdentifier = "ConfigTextEditCell"
            
            var leftLabel: UILabel? = nil
            var editField: UITextField? = nil
            
            let cell = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.objectForKey("DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
            }
            
            editField = cell?.viewWithTag(EDIT_TAG) as? UITextField
            
            /* Load the approprate field to edit */
            var rl = editFields?.objectForKey(displayName!) as? NSString
            if rl == nil {
                
                /* Is this if from the database... */
                if let dbAttribute = config.objectForKey("DBAttribute") as? NSString {
                    logger.log(.DEBUG, message: "Loading string from store")
                    rl = appConfiguration.getConfigItem(dbAttribute) as! NSString?
                }
                else if let _ = config.objectForKey("ConfigAttribute") as? NSString {
                    logger.log(.DEBUG, message: "Config only string - loading as blank")
                    rl = ""
                }
                else if let _ = config.objectForKey("Password")  {
                    rl = appConfiguration.getServicePassword()
                }
                
                if (rl == nil) {
                    rl = "";
                }
                
                editFields?.setValue(rl, forKey: displayName!)
            }
            else {
                logger.log(.FINE, message: "Loaded temporary empty string")
            }
        
            editField?.text = rl as String!
            editField?.delegate = self
            
            /* Is this a hidden field? */
            if let secureFromConf = config.objectForKey("SecureEntry") as? Bool {
                editField?.secureTextEntry = secureFromConf
            }
            else {
                editField?.secureTextEntry = false;
            }
            
            cell?.selectionStyle = UITableViewCellSelectionStyle.None
            return cell!

            
        }
        
        if (config.objectForKey("DBClass") != nil && config.objectForKey("DBClass") as? String == "Bool")  ||
           (config.objectForKey("ConfigClass") != nil && config.objectForKey("ConfigClass") as? String == "Bool") {
            
            logger.log(.FINE, message: "Creating a cell for a boolean value")
            
            // A Boolean value
            let LEFT_LABEL_TAG = 2020
            let SWITCH_TAG = 2021
            let cellIdentifier = "ConfigBoolCell"
            
            var leftLabel: UILabel? = nil
            var switchField: UISwitch? = nil
            
            let cell = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.objectForKey("DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
                logger.log(.ERROR, message: "Config item without DisplayNameShort")
            }
            
            switchField = cell?.viewWithTag(SWITCH_TAG) as? UISwitch
            switchField?.addTarget(self, action: #selector(ConfigurationDetailMenuController.switchTapped(_:)), forControlEvents: UIControlEvents.ValueChanged)
            
            var valueToEdit: Bool? = nil
            /* Load the approprate field to edit */
            if let valueToEditObject = editFields?.objectForKey(displayName!) as? NSNumber {
                valueToEdit = valueToEditObject.boolValue
            }
            
            if valueToEdit == nil {
                if let dbAttribute = config.objectForKey("DBAttribute") as? NSString {
                    logger.log(.DEBUG, message: "Loading Boolean value from store")
                    if let numberValueToEdit = appConfiguration.getConfigItem(dbAttribute) as? NSNumber {
                        valueToEdit = numberValueToEdit.boolValue
                    }
                }
                    
                else if let _ = config.objectForKey("ConfigAttribute") as? NSString {
                    logger.log(.DEBUG, message: "Loading Boolean config default value")
                    if let numberValueToEdit = config.objectForKey("DefaultValue") as? NSNumber {
                        valueToEdit = numberValueToEdit.boolValue
                    }
                }
            }
            
            if valueToEdit == nil {
                logger.log(.ERROR, message: "Error retrieving value from store")
                valueToEdit = true
            }
            
            switchField?.setOn(valueToEdit!, animated: false)
            
            editFields?.setValue(NSNumber(bool: valueToEdit!), forKey: displayName!)
                        
            cell?.selectionStyle = UITableViewCellSelectionStyle.None
            return cell!

            
        }
        
        if config.objectForKey("SpecialAction") != nil {
            
            // THis is a "special" cell.  Have to hard wire some stuff
            let LEFT_LABEL_TAG = 2010
            let cellIdentifier = "ConfigSpecialCell"
            
            var leftLabel: UILabel? = nil
            
            let cell = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.objectForKey("DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
            }
            
            cell?.selectionStyle = UITableViewCellSelectionStyle.None
            return cell!
            
            
        }
        
        return UITableViewCell()
        
        
    }
    
    // MARK: Table data handling
    
    override func numberOfSectionsInTableView(tableView: UITableView) -> Int {
        // Return the number of sections.
        
        if configTemplate != nil {
            return configTemplate!.count
        }
        
        return 0
        
    }
    
    override func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        
        var count = 0

        if let dict = configTemplate?.objectAtIndex(section) as? NSDictionary {
            if let array = dict.objectForKey("ConfigurationItems") as? NSArray {
                for configObject : AnyObject in array {
                    if let config = configObject as? NSDictionary {
                        if let configKey = config.objectForKey("ConfigDepends") as? NSString {
                            // We depend on something!
                            if let configVal = editFields?.objectForKey(configKey) as? NSNumber {
                                if configVal.boolValue {
                                    count += 1
                                }
                            }
                        }
                        else {
                            count += 1
                        }
                    }
                }
                
            }
        }
        
        return count
        
    }
    
    override func tableView(tableView: UITableView, titleForHeaderInSection section: Int) -> String {
        
        if let dict = configTemplate?.objectAtIndex(section) as? NSDictionary {
            if let str = dict.objectForKey("GroupName") as? String {
                return str
            }
        }
        
        return "Unknown Group"
        
    }
    
    override func tableView(tableView: UITableView, titleForFooterInSection section: Int) -> String {
        if let dict = configTemplate?.objectAtIndex(section) as? NSDictionary {
            if let str = dict.objectForKey("GroupDescription") as? String {
                return str
            }
        }
        
        return ""
        
    }
    
    override func tableView(tableView: UITableView, canEditRowAtIndexPath indexPath: NSIndexPath) -> Bool {
        // Return false if you do not want the specified item to be editable.
        return false
    }
    
    // MARK: Text field delegate methods
    func textFieldDidBeginEditing(textField: UITextField) {
        currentTextField = textField
        didEdit = true
    }
    
    func textFieldDidEndEditing(textField: UITextField) {
        let cell = textField.superview?.superview
        
        if cell == nil {
            return
        }
        
        /* For iOS 7 - no longer rely on the view hierarchy */
        let pos = textField.convertPoint(CGPointZero, toView:self.tableView)
        if let indexPath = self.tableView.indexPathForRowAtPoint(pos) {
            if let configDict = configTemplate!.objectAtIndex(indexPath.section) as? NSDictionary {
                if let configArray = configDict.objectForKey("ConfigurationItems") as? NSArray {
                    let dict = configArray.objectAtIndex(indexPath.row) as! NSDictionary
                    if let key = dict.objectForKey("DisplayNameShort")  as? NSString {
                        editFields?.setValue(textField.text, forKey: key as String)
                    }
                    
                }
            }
        }
    }
    
    func textFieldShouldReturn(textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return false
    }
    
    override func tableView(tableView: UITableView, didSelectRowAtIndexPath indexPath: NSIndexPath) {
        
        /* First find the configuration item we are dealing with */
        if let configDict = configTemplate!.objectAtIndex(indexPath.section) as? NSDictionary {
            if let configArray = configDict.objectForKey("ConfigurationItems") as? NSArray {
                let dict = configArray.objectAtIndex(indexPath.row) as! NSDictionary
                
                // Got the right config spot - see if we need to do anything special
                if let _ = dict.objectForKey("SpecialAction") as? NSString {
                    
                    // Nothing in here for now
                    logger.log(.DEBUG, message: "Somehow got a special action?")
                }
            }
        }
    }
    
    // MARK: Detect switch changes
    func switchTapped(uiSwitch: UISwitch) {
        logger.log(.FINEST, message: "Value of config switch changed")
        
        /* Find what switch it was */
        let position = uiSwitch.convertPoint(CGPointZero, toView: self.tableView)
        if let indexPath = self.tableView.indexPathForRowAtPoint(position) {
            
            // Get this value from the config
            let dict = configTemplate?.objectAtIndex(indexPath.section) as! NSDictionary
            if let sectionConfig = dict.objectForKey("ConfigurationItems") as? NSArray {
                if let config = sectionConfig.objectAtIndex(indexPath.row) as? NSDictionary {
                    if let dbAttribute = config.objectForKey("DBAttribute") as? NSString {
                        logger.log(.DEBUG, message: "Updating state for \(dbAttribute)")
                        let appConfiguration = AppConfiguration.getInstance()
                            appConfiguration.setConfigItem(dbAttribute, value: NSNumber(bool: uiSwitch.on))
                    }
                    else if let _ = config.objectForKey("ConfigAttribute") as? NSString {
                        if let displayName = config.objectForKey("DisplayNameShort") as? NSString {
                            // This is an internal only switch - need to store its state
                            // and then reload the table
                            logger.log(.FINE, message: "Config switch state changed")
                            editFields?.setValue(NSNumber(bool: uiSwitch.on), forKey: displayName as String)
                            
                            // Reload
                            self.tableView.reloadData()
                        }
                        else {
                            logger.log(.ERROR, message: "Unable to load DisplayNameShort for switch value")
                        }
                    }
                }
            }
        }
    }
    
    // MARK: Hardwired Calls
    func hardWired(function: String) {
        
        switch function {
        
        case "createNewUser":
            createNewUser()
        case "updateUserDetails":
            updateUserDetails()
        default:
            logger.log(.ERROR, message: "Unknown selector in configuration \(function)")
        }
    }

    // MARK: Save and update
    func errorMessage(title: String, message: String) {
    
        let alert = UIAlertController(title: title,
            message: message, preferredStyle: UIAlertControllerStyle.Alert)
        alert.addAction(UIAlertAction(title: "OK", style: UIAlertActionStyle.Default, handler: nil))
        self.presentViewController(alert, animated: false, completion: nil)

    }
    
    func runLoopDismiss() {
        // Put this on the run-loop so it executes after we shut down
        logger.log(.DEBUG, message: "Dismissing controller")
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, Int64((Double(0.25)) * Double(NSEC_PER_SEC))), dispatch_get_main_queue(), {
            if let nav = self.splitViewController?.viewControllers[0] as? UINavigationController {
                nav.popViewControllerAnimated(true)
            }
            else {
                self.logger.log(.DEBUG, message: "No nav controller????")
            }
        })
    }
    
    func createNewUser() {
        
        logger.log(.DEBUG, message: "Trying to create new user")
        let name = editFields?.objectForKey("Name") as? String
        let password = editFields?.objectForKey("Password") as? String
        let passwordRepeat = editFields?.objectForKey("Repeat PW") as? String
        let userId = editFields?.objectForKey("Username") as? String
        let email = editFields?.objectForKey("Email") as? String
        
        if name == nil || name == "" {
            errorMessage("Error Creating User", message: "Name cannot be blank")
            return
        }
        
        if userId == nil || userId == "" {
            errorMessage("Error Creating User", message: "Username cannot be blank")
            return
        }
        
        if email == nil || email == "" {
            errorMessage("Error Creating User", message: "Email address cannot be blank")
            return
        }
        
        if email?.rangeOfString("@") == nil {
            errorMessage("Error Creating User", message: "Email address must contain a '@' character")
            return
        }
        
        if (password == nil) ||
            (passwordRepeat == nil) ||
            (password != passwordRepeat) ||
            (password!.utf8.count < 6) {
            
                errorMessage("Error Creating User", message: "Password and password repeat must match and be greater than 5 characters.")
                return
        }
/*
        readercomService.createUser(editFields!.objectForKey("Email") as! String,
            name: editFields?.objectForKey("Name") as! String,
            userId: editFields?.objectForKey("Username") as! String,
            password: editFields?.objectForKey("Password") as! String)
*/
        
        visibleAlert = UIAlertController(title: "Creating User",
            message: "Connecting to AuthMe service to create user", preferredStyle: UIAlertControllerStyle.Alert)
        self.presentViewController(visibleAlert!, animated: true, completion: nil)
    
    }
    
    func updateUserDetails() {
        
        let amsi = AuthMeServiceInitialiser()
        amsi.doInit()
        
    }

    func save(sender: AnyObject) {
        
        didEdit = false
        //var updatedUserDetails = false
        
        currentTextField?.resignFirstResponder()
        
        let appConfiguration = AppConfiguration.getInstance()
        
        for var i = 0; i <  configTemplate?.count ; i += 1 {
            
            let dict = configTemplate?.objectAtIndex(i) as! NSDictionary
            if let sectionConfig = dict.objectForKey("ConfigurationItems") as? NSArray {
            
                for j in 0 ..< sectionConfig.count {
                    
                    if let config = sectionConfig.objectAtIndex(j) as? NSDictionary {
                        if let storageKey = config.objectForKey("DisplayNameShort") as? NSString {
                            if let value = editFields!.objectForKey(storageKey) as? NSString {
                                if let dbAttribute = config.objectForKey("DBAttribute") as? NSString {
                                    appConfiguration.setConfigItem(dbAttribute, value: value)
                                }
                                else  {
                                    appConfiguration.setServicePassword(value)
                                }
                            }
                            else if let _ = config.objectForKey("ConfigSelector") as? NSNumber {
                                // This potentially calls functions in the current class
                                if let value = editFields!.objectForKey(storageKey) as? NSNumber {
                                    if value.boolValue {
                                        if let selector = config.valueForKey("CallOnTrue") as? NSString {
                                            // A selector to call!
                                            hardWired(selector as String)
                                        }
                                    }
                                    else {
                                        if let selector = config.valueForKey("CallOnFalse") as? NSString {
                                            hardWired(selector as String)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
}

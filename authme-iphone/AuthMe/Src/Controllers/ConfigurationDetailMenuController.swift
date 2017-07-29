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
// FIXME: comparison operators with optionals were removed from the Swift Standard Libary.
// Consider refactoring the code to use the non-optional operators.
fileprivate func < <T : Comparable>(lhs: T?, rhs: T?) -> Bool {
  switch (lhs, rhs) {
  case let (l?, r?):
    return l < r
  case (nil, _?):
    return true
  default:
    return false
  }
}


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
        if let configCount = configTemplate?.count {
            for var i in 0...configCount {
                //        for var i = 0; i <  configTemplate?.count ; i += 1 {
                
                let dict = configTemplate?.object(at: i) as! NSDictionary
                if let sectionConfig = dict.object(forKey: "ConfigurationItems") as? NSArray {
                    
                    for j in 0 ..< sectionConfig.count {
                        
                        if let config = sectionConfig.object(at: j) as? NSDictionary {
                            if  (config.object(forKey: "DBClass") != nil && config.object(forKey: "DBClass") as? String == "String") ||
                                config.object(forKey: "InputType") != nil ||
                                config.object(forKey: "KeyChainService") != nil {
                                
                                let saveButton = UIBarButtonItem(barButtonSystemItem: .save, target: self, action: #selector(ConfigurationDetailMenuController.save(_:)))
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
        
    }
    
    override func viewWillDisappear(_ animated: Bool) {
        if didEdit {
            logger.log(.debug, message: "User navigated away without saving changes")
            let alert = UIAlertController(title: "Save Changes?",
                message: "You have not saved your changes - do you want to do so?",
                preferredStyle: UIAlertControllerStyle.alert)
            
            alert.addAction(UIAlertAction(title: "Yes", style: UIAlertActionStyle.default, handler: { action in
                self.save(self)
                
            }))
            alert.addAction(UIAlertAction(title: "No", style: UIAlertActionStyle.cancel, handler: nil))
            self.present(alert, animated:true, completion: nil)
        }
    }
    
    override func viewWillAppear(_ animated: Bool) {
        
        // If we were swapped out - reload
        
        //editFields = NSMutableDictionary()
        self.tableView.reloadData()
        //if let visibleCells = self.tableView.indexPathsForVisibleRows() {
        //  self.tableView.reloadRowsAtIndexPaths(visibleCells, withRowAnimation: UITableViewRowAnimation.Automatic)
        //}
        
    }
    
    
    override func willAnimateRotation(to toInterfaceOrientation: UIInterfaceOrientation, duration: TimeInterval) {

        if let visibleCells = self.tableView.indexPathsForVisibleRows {
            self.tableView.reloadRows(at: visibleCells, with: UITableViewRowAnimation.automatic)
        }
    }

    
    // MARK: Cell Handling
    override func tableView(_ tableView: UITableView, willDisplay cell: UITableViewCell, forRowAt indexPath: IndexPath) {
        
        /* Give us a nice "configuration look" cell.  Taken from a 
         * stackoverflow.com answer and converted to swift.
         * See: http://stackoverflow.com/questions/18822619/ios-7-tableview-like-in-settings-app-on-ipad
        */
        
        if cell.responds(to: #selector(getter: UIView.tintColor)) {
            if tableView == self.tableView {
                
                /* This is us! */
                let cornerRadius: CGFloat  = 5
                cell.backgroundColor = UIColor.clear
                let layer = CAShapeLayer()
                let pathRef = CGMutablePath()
                let bounds = cell.bounds.insetBy(dx: 10, dy: 0)
                let tableBounds = tableView.bounds
                logger.log(.debug, message: "cell width = \(cell.bounds.width) table width = \(tableBounds.width) view width = \(self.view.bounds.width)")
                //var bounds = CGRectInset(cell.frame, 10, 0)
                
                var addLine = false
                
                /* Case of a singleton cell? */
                if indexPath.row == 0 && indexPath.row == tableView.numberOfRows(inSection: indexPath.section) - 1 {
                    pathRef.__addRoundedRect(transform: nil, rect: bounds, cornerWidth: cornerRadius, cornerHeight: cornerRadius)
                }
                
                /* Top cell of a multi cell group */
                else if indexPath.row == 0 {
                    pathRef.move(to: CGPoint(x: bounds.minX, y: bounds.maxY))
                    pathRef.addArc(tangent1End: CGPoint(x: bounds.minX, y: bounds.minY), tangent2End: CGPoint(x: bounds.midX, y: bounds.minY), radius: cornerRadius)
                    pathRef.addArc(tangent1End: CGPoint(x: bounds.maxX, y: bounds.minY), tangent2End: CGPoint(x: bounds.maxX, y: bounds.midY), radius: cornerRadius)
                    pathRef.addLine(to: CGPoint(x: bounds.maxX, y: bounds.maxY))
                    addLine = true
                }
                    
                /* Bottom cell of a multi cell group */
                else if indexPath.row == (tableView.numberOfRows(inSection: indexPath.section) - 1) {
                    
                    pathRef.move(to: CGPoint(x: bounds.minX, y: bounds.minY))
                    pathRef.addArc(tangent1End: CGPoint(x: bounds.minX, y: bounds.maxY), tangent2End: CGPoint(x: bounds.midX, y: bounds.maxY), radius: cornerRadius)
                    pathRef.addArc(tangent1End: CGPoint(x: bounds.maxX, y: bounds.maxY), tangent2End: CGPoint(x: bounds.maxX, y: bounds.midY), radius: cornerRadius)
                    pathRef.addLine(to: CGPoint(x: bounds.maxX, y: bounds.minY))
                }
                
                else {
                    pathRef.addRect(bounds)
                    addLine = true;
                }
                
                /* Now plot it */
                layer.path = pathRef
                //CFRelease(pathRef) - not required - automatically released now
                layer.fillColor = UIColor(white: 1.0, alpha: 0.8).cgColor
                
                if addLine {
                    let lineLayer = CALayer()
                    let lineHeight = 1.0 / UIScreen.main.scale
                    lineLayer.frame = CGRect(x: bounds.minX+10, y: bounds.size.height-lineHeight, width: bounds.size.width-10, height: lineHeight)
                    lineLayer.backgroundColor = tableView.separatorColor!.cgColor;
                    layer.addSublayer(lineLayer)
                }
                
                /* Now add it! */
                let toAdd = UIView(frame: bounds)
                toAdd.layer.insertSublayer(layer, at: 0)
                toAdd.backgroundColor = UIColor.clear
                cell.backgroundView = toAdd
                
                /* Now for when selected */
                let bgLayer = CAShapeLayer()
                bgLayer.path = pathRef
                bgLayer.fillColor = UIColor(red: (76.0/255), green: (161.0/255.0), blue: 1.0, alpha: 1.0).cgColor
                
                let bgColourView = UIView(frame: bounds)
                bgColourView.layer.insertSublayer(bgLayer, at: 0)
                bgColourView.layer.masksToBounds = true;
                cell.selectedBackgroundView = bgColourView;

                
            }
        }
        
    }
    
    // Customize the appearance of table view cells.
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        
        logger.log(.fine, message: "At start of cellForRowAtIndexPath")
        
        /* Load the specific configuration section for where we are */
        var _config: NSDictionary? = nil
        
        if let dict = configTemplate?.object(at: indexPath.section) as? NSDictionary {
            if let array = dict.object(forKey: "ConfigurationItems") as? NSArray {
                _config = array.object(at: indexPath.row) as? NSDictionary
            }
        }
        
        if _config == nil {
            logger.log(.error, message: "Error loading configTemplate")
            return UITableViewCell()
        }
        
        let config = _config! as NSDictionary
        let appConfiguration = AppConfiguration.getInstance()
        
        /* What kind of cell should we load? */
        if  (config.object(forKey: "DBClass") != nil && config.object(forKey: "DBClass") as? String == "String") ||
            (config.object(forKey: "ConfigClass") != nil && config.object(forKey: "ConfigClass") as? String == "String") ||
            config.object(forKey: "InputType") != nil ||
            config.object(forKey: "Password") != nil {
            
            // Something we're going to save in a database
            let LEFT_LABEL_TAG = 2001
            let EDIT_TAG = 2002
            let cellIdentifier = "ConfigTextEditCell"
            
            var leftLabel: UILabel? = nil
            var editField: UITextField? = nil
            
            let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.object(forKey: "DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
            }
            
            editField = cell?.viewWithTag(EDIT_TAG) as? UITextField
            
            /* Load the approprate field to edit */
            var rl = editFields?.object(forKey: displayName!) as? NSString
            if rl == nil {
                
                /* Is this if from the database... */
                if let dbAttribute = config.object(forKey: "DBAttribute") as? NSString {
                    logger.log(.debug, message: "Loading string from store")
                    rl = appConfiguration.getConfigItem(dbAttribute) as! NSString?
                }
                else if let _ = config.object(forKey: "ConfigAttribute") as? NSString {
                    logger.log(.debug, message: "Config only string - loading as blank")
                    rl = ""
                }
                else if let _ = config.object(forKey: "Password")  {
                    rl = appConfiguration.getServicePassword() as NSString?
                }
                
                if (rl == nil) {
                    rl = "";
                }
                
                editFields?.setValue(rl, forKey: displayName!)
            }
            else {
                logger.log(.fine, message: "Loaded temporary empty string")
            }
        
            editField?.text = rl as String!
            editField?.delegate = self
            
            /* Is this a hidden field? */
            if let secureFromConf = config.object(forKey: "SecureEntry") as? Bool {
                editField?.isSecureTextEntry = secureFromConf
            }
            else {
                editField?.isSecureTextEntry = false;
            }
            
            cell?.selectionStyle = UITableViewCellSelectionStyle.none
            return cell!

            
        }
        
        if (config.object(forKey: "DBClass") != nil && config.object(forKey: "DBClass") as? String == "Bool")  ||
           (config.object(forKey: "ConfigClass") != nil && config.object(forKey: "ConfigClass") as? String == "Bool") {
            
            logger.log(.fine, message: "Creating a cell for a boolean value")
            
            // A Boolean value
            let LEFT_LABEL_TAG = 2020
            let SWITCH_TAG = 2021
            let cellIdentifier = "ConfigBoolCell"
            
            var leftLabel: UILabel? = nil
            var switchField: UISwitch? = nil
            
            let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.object(forKey: "DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
                logger.log(.error, message: "Config item without DisplayNameShort")
            }
            
            switchField = cell?.viewWithTag(SWITCH_TAG) as? UISwitch
            switchField?.addTarget(self, action: #selector(ConfigurationDetailMenuController.switchTapped(_:)), for: UIControlEvents.valueChanged)
            
            var valueToEdit: Bool? = nil
            /* Load the approprate field to edit */
            if let valueToEditObject = editFields?.object(forKey: displayName!) as? NSNumber {
                valueToEdit = valueToEditObject.boolValue
            }
            
            if valueToEdit == nil {
                if let dbAttribute = config.object(forKey: "DBAttribute") as? NSString {
                    logger.log(.debug, message: "Loading Boolean value from store")
                    if let numberValueToEdit = appConfiguration.getConfigItem(dbAttribute) as? NSNumber {
                        valueToEdit = numberValueToEdit.boolValue
                    }
                }
                    
                else if let _ = config.object(forKey: "ConfigAttribute") as? NSString {
                    logger.log(.debug, message: "Loading Boolean config default value")
                    if let numberValueToEdit = config.object(forKey: "DefaultValue") as? NSNumber {
                        valueToEdit = numberValueToEdit.boolValue
                    }
                }
            }
            
            if valueToEdit == nil {
                logger.log(.error, message: "Error retrieving value from store")
                valueToEdit = true
            }
            
            switchField?.setOn(valueToEdit!, animated: false)
            
            editFields?.setValue(NSNumber(value: valueToEdit! as Bool), forKey: displayName!)
                        
            cell?.selectionStyle = UITableViewCellSelectionStyle.none
            return cell!

            
        }
        
        if config.object(forKey: "SpecialAction") != nil {
            
            // THis is a "special" cell.  Have to hard wire some stuff
            let LEFT_LABEL_TAG = 2010
            let cellIdentifier = "ConfigSpecialCell"
            
            var leftLabel: UILabel? = nil
            
            let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier) as UITableViewCell?
            leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
            
            var displayName = config.object(forKey: "DisplayNameShort") as? String
            if displayName != nil {
                leftLabel?.text = displayName!
            }
            else {
                displayName = "ERROR IN CONFIG"
                leftLabel?.text = "fff"
            }
            
            cell?.selectionStyle = UITableViewCellSelectionStyle.none
            return cell!
            
            
        }
        
        return UITableViewCell()
        
        
    }
    
    // MARK: Table data handling
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        // Return the number of sections.
        
        if configTemplate != nil {
            return configTemplate!.count
        }
        
        return 0
        
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        
        var count = 0

        if let dict = configTemplate?.object(at: section) as? NSDictionary {
            if let array = dict.object(forKey: "ConfigurationItems") as? NSArray {
                for configObject : AnyObject in array as [AnyObject] {
                    if let config = configObject as? NSDictionary {
                        if let configKey = config.object(forKey: "ConfigDepends") as? NSString {
                            // We depend on something!
                            if let configVal = editFields?.object(forKey: configKey) as? NSNumber {
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
    
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String {
        
        if let dict = configTemplate?.object(at: section) as? NSDictionary {
            if let str = dict.object(forKey: "GroupName") as? String {
                return str
            }
        }
        
        return "Unknown Group"
        
    }
    
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String {
        if let dict = configTemplate?.object(at: section) as? NSDictionary {
            if let str = dict.object(forKey: "GroupDescription") as? String {
                return str
            }
        }
        
        return ""
        
    }
    
    override func tableView(_ tableView: UITableView, canEditRowAt indexPath: IndexPath) -> Bool {
        // Return false if you do not want the specified item to be editable.
        return false
    }
    
    // MARK: Text field delegate methods
    func textFieldDidBeginEditing(_ textField: UITextField) {
        currentTextField = textField
        didEdit = true
    }
    
    func textFieldDidEndEditing(_ textField: UITextField) {
        let cell = textField.superview?.superview
        
        if cell == nil {
            return
        }
        
        /* For iOS 7 - no longer rely on the view hierarchy */
        let pos = textField.convert(CGPoint.zero, to:self.tableView)
        if let indexPath = self.tableView.indexPathForRow(at: pos) {
            if let configDict = configTemplate!.object(at: indexPath.section) as? NSDictionary {
                if let configArray = configDict.object(forKey: "ConfigurationItems") as? NSArray {
                    let dict = configArray.object(at: indexPath.row) as! NSDictionary
                    if let key = dict.object(forKey: "DisplayNameShort")  as? NSString {
                        editFields?.setValue(textField.text, forKey: key as String)
                    }
                    
                }
            }
        }
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return false
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        
        /* First find the configuration item we are dealing with */
        if let configDict = configTemplate!.object(at: indexPath.section) as? NSDictionary {
            if let configArray = configDict.object(forKey: "ConfigurationItems") as? NSArray {
                let dict = configArray.object(at: indexPath.row) as! NSDictionary
                
                // Got the right config spot - see if we need to do anything special
                if let _ = dict.object(forKey: "SpecialAction") as? NSString {
                    
                    // Nothing in here for now
                    logger.log(.debug, message: "Somehow got a special action?")
                }
            }
        }
    }
    
    // MARK: Detect switch changes
    func switchTapped(_ uiSwitch: UISwitch) {
        logger.log(.finest, message: "Value of config switch changed")
        
        /* Find what switch it was */
        let position = uiSwitch.convert(CGPoint.zero, to: self.tableView)
        if let indexPath = self.tableView.indexPathForRow(at: position) {
            
            // Get this value from the config
            let dict = configTemplate?.object(at: indexPath.section) as! NSDictionary
            if let sectionConfig = dict.object(forKey: "ConfigurationItems") as? NSArray {
                if let config = sectionConfig.object(at: indexPath.row) as? NSDictionary {
                    if let dbAttribute = config.object(forKey: "DBAttribute") as? NSString {
                        logger.log(.debug, message: "Updating state for \(dbAttribute)")
                        let appConfiguration = AppConfiguration.getInstance()
                            appConfiguration.setConfigItem(dbAttribute, value: NSNumber(value: uiSwitch.isOn as Bool))
                    }
                    else if let _ = config.object(forKey: "ConfigAttribute") as? NSString {
                        if let displayName = config.object(forKey: "DisplayNameShort") as? NSString {
                            // This is an internal only switch - need to store its state
                            // and then reload the table
                            logger.log(.fine, message: "Config switch state changed")
                            editFields?.setValue(NSNumber(value: uiSwitch.isOn as Bool), forKey: displayName as String)
                            
                            // Reload
                            self.tableView.reloadData()
                        }
                        else {
                            logger.log(.error, message: "Unable to load DisplayNameShort for switch value")
                        }
                    }
                }
            }
        }
    }
    
    // MARK: Hardwired Calls
    func hardWired(_ function: String) {
        
        switch function {
        
        case "createNewUser":
            createNewUser()
        case "updateUserDetails":
            updateUserDetails()
        default:
            logger.log(.error, message: "Unknown selector in configuration \(function)")
        }
    }

    // MARK: Save and update
    func errorMessage(_ title: String, message: String) {
    
        let alert = UIAlertController(title: title,
            message: message, preferredStyle: UIAlertControllerStyle.alert)
        alert.addAction(UIAlertAction(title: "OK", style: UIAlertActionStyle.default, handler: nil))
        self.present(alert, animated: false, completion: nil)

    }
    
    func runLoopDismiss() {
        // Put this on the run-loop so it executes after we shut down
        logger.log(.debug, message: "Dismissing controller")
        DispatchQueue.main.asyncAfter(deadline: DispatchTime.now() + Double(Int64((Double(0.25)) * Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC), execute: {
            if let nav = self.splitViewController?.viewControllers[0] as? UINavigationController {
                nav.popViewController(animated: true)
            }
            else {
                self.logger.log(.debug, message: "No nav controller????")
            }
        })
    }
    
    func createNewUser() {
        
        logger.log(.debug, message: "Trying to create new user")
        let name = editFields?.object(forKey: "Name") as? String
        let password = editFields?.object(forKey: "Password") as? String
        let passwordRepeat = editFields?.object(forKey: "Repeat PW") as? String
        let userId = editFields?.object(forKey: "Username") as? String
        let email = editFields?.object(forKey: "Email") as? String
        
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
        
        if email?.range(of: "@") == nil {
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
            message: "Connecting to AuthMe service to create user", preferredStyle: UIAlertControllerStyle.alert)
        self.present(visibleAlert!, animated: true, completion: nil)
    
    }
    
    func updateUserDetails() {
        
        let amsi = AuthMeServiceInitialiser()
        amsi.doInit()
        
    }

    func save(_ sender: AnyObject) {
        
        didEdit = false
        //var updatedUserDetails = false
        
        currentTextField?.resignFirstResponder()
        
        let appConfiguration = AppConfiguration.getInstance()
        
        if let configTemplateCount = configTemplate?.count {
            for i in 0..<configTemplateCount {
                
                let dict = configTemplate?.object(at: i) as! NSDictionary
                if let sectionConfig = dict.object(forKey: "ConfigurationItems") as? NSArray {
                    
                    for j in 0 ..< sectionConfig.count {
                        
                        if let config = sectionConfig.object(at: j) as? NSDictionary {
                            if let storageKey = config.object(forKey: "DisplayNameShort") as? NSString {
                                if let value = editFields!.object(forKey: storageKey) as? NSString {
                                    if let dbAttribute = config.object(forKey: "DBAttribute") as? NSString {
                                        appConfiguration.setConfigItem(dbAttribute, value: value)
                                    }
                                    else  {
                                        appConfiguration.setServicePassword(value)
                                    }
                                }
                                else if let _ = config.object(forKey: "ConfigSelector") as? NSNumber {
                                    // This potentially calls functions in the current class
                                    if let value = editFields!.object(forKey: storageKey) as? NSNumber {
                                        if value.boolValue {
                                            if let selector = config.value(forKey: "CallOnTrue") as? NSString {
                                                // A selector to call!
                                                hardWired(selector as String)
                                            }
                                        }
                                        else {
                                            if let selector = config.value(forKey: "CallOnFalse") as? NSString {
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
    
}

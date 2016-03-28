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
//  ConfigurationMainMenuController.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 6/09/2014.
//  Copyright (c) 2014 Berin Lautenbach. All rights reserved.
//

import UIKit
import Foundation

class ConfigurationMainMenuController: UITableViewController {
    
    var logger = Log()
    var firstAppearance = true
    
    let configTemplatePlist = "ConfigurationSetup"
    
    var currentIndexPath: NSIndexPath? = nil
    var detailMenuController: ConfigurationDetailMenuController? = nil
    var storedEditFields: NSMutableDictionary? = nil
    
    // MARK: Setup and teardown
    
    override func awakeFromNib() {
        super.awakeFromNib()
        if UIDevice.currentDevice().userInterfaceIdiom == .Pad {
            self.clearsSelectionOnViewWillAppear = false
            self.preferredContentSize = CGSize(width: 320.0, height: 600.0)
        }
        
        
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        self.navigationItem.title = "Config"
        if let split = self.splitViewController {
            let controllers = split.viewControllers
            self.detailMenuController = (controllers[controllers.count-1] as! UINavigationController).topViewController as? ConfigurationDetailMenuController
        }
        
        self.tableView.estimatedRowHeight = 44;
        self.tableView.rowHeight = UITableViewAutomaticDimension;
        
    }
    
    override func viewDidAppear(animated: Bool) {
        if firstAppearance {
            firstAppearance = false
            
            let appConfiguration = AppConfiguration.getInstance()
            if appConfiguration.getConfigItem("serviceUsername") as! String? == nil ||
                appConfiguration.getConfigItem("serviceUsername") as! String? == "" {
                    logger.log(.DEBUG, message: "Loading for no username")
                    self.tableView.selectRowAtIndexPath(NSIndexPath(forItem: 0, inSection: 0), animated: true, scrollPosition: UITableViewScrollPosition.Bottom)
                    self.performSegueWithIdentifier("showConfigDetail", sender: self)
                    //self.tableView(self.tableView, selectRowAtIndexPath: NSIndexPath(forItem: 0, inSection: 0))
                    
                    // Tell the user they need to take some action
                    let alert = UIAlertController(title: "Credentials Required",
                    message: "Please enter credentials or create a new account for the AuthMe service", preferredStyle: UIAlertControllerStyle.Alert)
                    alert.addAction(UIAlertAction(title: "OK", style: UIAlertActionStyle.Default, handler: nil))
                    self.presentViewController(alert, animated: true, completion: nil)
                    

            }
        }
    }
    
    override func viewWillAppear(animated: Bool) {
        
        // If we were swapped out - reload
        if let visibleCells = self.tableView.indexPathsForVisibleRows {
            self.tableView.reloadRowsAtIndexPaths(visibleCells, withRowAnimation: UITableViewRowAnimation.Automatic)
        }
        
        if self.splitViewController != nil {
            if (currentIndexPath != nil) && !(self.splitViewController!.collapsed) {
                storedEditFields = detailMenuController?.editFields
                self.tableView.selectRowAtIndexPath(currentIndexPath, animated: false, scrollPosition: UITableViewScrollPosition.None)
                self.performSegueWithIdentifier("showConfigDetail", sender: self)
                storedEditFields = nil
            }
        }
    }

    override func shouldAutorotate() -> Bool {
        return true
    }
    
    // MARK: - Segues
    
    override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
        if segue.identifier == "showConfigDetail" && self.splitViewController != nil {
            if let indexPath = self.tableView.indexPathForSelectedRow {
                currentIndexPath = indexPath
                //let object = self.feedUpdateController.feedAtIndexPath(indexPath)
                let controller = (segue.destinationViewController as! UINavigationController).topViewController as! ConfigurationDetailMenuController
                var _config: NSDictionary? = nil
                if let dict = configTemplate.objectAtIndex(indexPath.section) as? NSDictionary {
                    if let array = dict.objectForKey("ConfigurationItems") as? NSArray {
                        _config = array.objectAtIndex(indexPath.row) as? NSDictionary
                    }
                }
                let newConfigArray = _config?.objectForKey("SubMenu") as? NSArray
                controller.configTemplate = newConfigArray
                detailMenuController = controller
                
                //controller.detailItem = object
                //controller.masterViewController = self
                //controller.navigationItem.leftBarButtonItem = UIBarButtonItem(title: "test", style: UIBarButtonItemStyle.Plain, target: self.splitViewController!.displayModeButtonItem().target, action: self.splitViewController!.displayModeButtonItem().action)// self.splitViewController!.displayModeButtonItem()
                
                if let subTitle = _config?.objectForKey("DisplayNameShort") as? NSString {
                    controller.navigationItem.title = subTitle as String
                }
                else {
                    controller.navigationItem.title = "Configuration"
                }
                
                controller.editFields = storedEditFields
            }
        }
    }

    
    // MARK: Data Source
    
    override func numberOfSectionsInTableView(tableView: UITableView) -> Int {
        // Return the number of sections.
        
        return configTemplate.count
        
    }
    
    override func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {

        if let dict = configTemplate.objectAtIndex(section) as? NSDictionary {
            if let array = dict.objectForKey("ConfigurationItems") as? NSArray {
                return array.count
            }
        }
        
        return 0
        
    }
    
    override func tableView(tableView: UITableView, titleForHeaderInSection section: Int) -> String {

        if let dict = configTemplate.objectAtIndex(section) as? NSDictionary {
            if let str = dict.objectForKey("GroupName") as? String {
                return str
            }
        }
        
        return "Unknown Group"
    
    }
    
    override func tableView(tableView: UITableView, titleForFooterInSection section: Int) -> String {
        if let dict = configTemplate.objectAtIndex(section) as? NSDictionary {
            if let str = dict.objectForKey("GroupDescription") as? String {
                return str
            }
        }
        
        return ""
        
    }
    
    /*
    override func tableView(tableView: UITableView!, heightForRowAtIndexPath indexPath: NSIndexPath!) -> CGFloat {
        return 44.0
    }
    */
    
    
    // MARK: Cell Configurer
    
    // Customize the appearance of table view cells.
    override func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        
        logger.log(.FINE, message: "At start of cellForRowAtIndexPath")
        
        
        /* Load the specific configuration section for where we are */
        var _config: NSDictionary? = nil
        
        if let dict = configTemplate.objectAtIndex(indexPath.section) as? NSDictionary {
            if let array = dict.objectForKey("ConfigurationItems") as? NSArray {
                _config = array.objectAtIndex(indexPath.row) as? NSDictionary
            }
        }
        
        if _config == nil {
            logger.log(.ERROR, message: "Error loading configTemplate")
            return UITableViewCell()
        }
        
        let config = _config! as NSDictionary
        
        /* At the base menu all cells are either for sub menus or selectors */
        let LEFT_LABEL_TAG = 1001
        let cellIdentifier = "MainMenuSelectorCell"
        
        var leftLabel: UILabel? = nil
        
        let cell = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) as UITableViewCell?
        leftLabel = cell?.viewWithTag(LEFT_LABEL_TAG) as? UILabel
        
        if let str = config.objectForKey("DisplayNameShort") as? String {
            leftLabel?.text = str
        }
        else {
            leftLabel?.text = ""
        }
        
        // This doesn't work in IOS7 and above
        //cell?.selectionStyle = UITableViewCellSelectionStyle.Blue
        
        // From http://stackoverflow.com/questions/18794080/ios7-uitableviewcell-selectionstyle-wont-go-back-to-blue
        let bgColourView = UIView()
        bgColourView.backgroundColor = UIColor(red: (76.0/255), green: (161.0/255.0), blue: 1.0, alpha: 1.0)
        bgColourView.layer.masksToBounds = true;
        cell?.selectedBackgroundView = bgColourView;
        
        return cell!
        
    }
    
    // MARK: Load the configuration template
    var configTemplate: NSArray {
        
        if _configTemplate != nil {
            return _configTemplate!
        }
            
        if let path = NSBundle.mainBundle().pathForResource(configTemplatePlist, ofType: "plist") {
            _configTemplate = NSArray(contentsOfFile: path)
        }
        else {
            _configTemplate = NSArray()
        }
            
        /* If we are in release mode, remove anything debug related */
        
        #if DEBUG
            logger.log(.DEBUG, message: "Loading DEBUG Configuration Items")
        #else
            let newConfigTemplate = NSMutableArray()
                
            for item in _configTemplate as! [NSDictionary] {
                if let confElementIsDebug = item.valueForKey("DebugOnly") as? Bool {
                    if !confElementIsDebug {
                        newConfigTemplate.addObject(item)
                    }
                }
                else {
                    newConfigTemplate.addObject(item)
                }
            }
            
            _configTemplate = newConfigTemplate
            
        #endif
            
        return _configTemplate!
            
    }
    
    var _configTemplate: NSArray? = nil
    

}
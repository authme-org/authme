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
//  ConfigurationSplitViewController.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 6/09/2014.
//  Copyright (c) 2014 Berin Lautenbach. All rights reserved.
//

import UIKit
import Foundation

class ConfigurationSplitViewController: UISplitViewController, UISplitViewControllerDelegate {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        self.delegate = self;
        
        self.preferredDisplayMode = .AllVisible
    }

    // MARK: - Split view
    
    func splitViewController(splitViewController: UISplitViewController, collapseSecondaryViewController secondaryViewController:UIViewController, ontoPrimaryViewController primaryViewController:UIViewController) -> Bool {
        if let secondaryAsNavController = secondaryViewController as? UINavigationController {
            if let _ = secondaryAsNavController.topViewController as? ConfigurationDetailMenuController {
                // Return true to indicate that we have handled the collapse by doing nothing; the secondary controller will be discarded.
                return true
            }
        }
        return true
    }

    func targetDisplayModeForActionInSplitViewController(svc: UISplitViewController) -> UISplitViewControllerDisplayMode {
        
        /* We always operate our config in split view */
        return .AllVisible
        
    }
    
}
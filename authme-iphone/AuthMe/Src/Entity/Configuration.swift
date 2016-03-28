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
//  Configuration.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 2/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation
import CoreData

class Configuration: NSManagedObject {

    @NSManaged var storeKey: String?
    @NSManaged var nextId: NSNumber
    @NSManaged var checkString: String?
    @NSManaged var checkStringRSA: String?
    @NSManaged var deviceKeyPublic: String?
    @NSManaged var deviceKeyPrivate: String?
    @NSManaged var deviceUUID: String?
    @NSManaged var useTouchID: NSNumber

}

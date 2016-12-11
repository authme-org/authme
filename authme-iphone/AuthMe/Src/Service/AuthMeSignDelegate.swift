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
//  AuthMeSignDelegate.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 30/01/2016.
//  Copyright © 2016 Berin Lautenbach. All rights reserved.
//

import Foundation

protocol AuthMeSignDelegate {
    
    func signerDidComplete(_ signer: AuthMeSign, didSucceed: Bool, withOpaqueData opaqueData: AnyObject?)
    
}

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
//  AuthMeServiceOperation.swift
//  AuthMe
//
//  Created by Berin Lautenbach on 8/03/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

import Foundation

class AuthMeServiceOperation: NSOperation, NSURLConnectionDelegate {
    
    var logger = Log()
    
    let serviceIdentifier = "readercom.com"
    let usernameKey = "serviceUsername"
    
    var url: NSURL? = nil
    var connection: NSURLConnection? = nil
    
    var returnData: NSMutableData? = nil
    var postData: NSData? = nil
    var error: NSError? = nil
    var secureRequest = false
    var statusCode: Int = 0
    
    /* Actually an opaque type to this guy */
    var operationType = AuthMeService.AuthMeOperationType.UnknownOperation
    var opaqueData: AnyObject? = nil
    var delegate: AuthMeServiceDelegate? = nil
    
    init(url: NSString) {
        
        self.url = NSURL(string: url as String)
        _executing = false;
        _finished = false;
        _concurrent = true;
        
    }
    
    override
    func start() {
        
        
        if !NSThread.isMainThread() {
            
            dispatch_async(dispatch_get_main_queue(), {
                
                self.start()
            })
            return;
        }
        
        if url == nil {
            logger.log(.ERROR, message: "Error in ReadercomServiceOperation - URL not defined")
            return
        }
        
        self.willChangeValueForKey("isExecuting")
        self.executing = true
        self.didChangeValueForKey("isExecuting")
        
        logger.log(.DEBUG, message: "Starting service thread for \(url)")
        
        /* Now kick off the connection! */
        let urlRequest = NSMutableURLRequest(URL: url!)
        
        /* For a post - add the right headers and the data to the request */
        if let toPost = postData {
            urlRequest.HTTPMethod = "PUT"
            let postLength = String(toPost.length)
            urlRequest.setValue(postLength, forHTTPHeaderField: "Content-Length")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.HTTPBody = toPost
        }
        
        if secureRequest == true {
            
            let appConfiguration = AppConfiguration.getInstance()
            
            // Need to add username and password
            if let username = appConfiguration.getConfigItem(usernameKey) as? String {
                if username != ""  { //appConfiguration.getConfigItem(usernameKey) as? String {
                    let usernamePassword = username + ":" + appConfiguration.getServicePassword()
                
                    if let raw = usernamePassword.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
                        let base64 = raw.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
                    
                        // Add to headers
                        let fullHeader = "Basic " + base64
                        urlRequest.setValue(fullHeader, forHTTPHeaderField: "Authorization")
                    }
                }
            }
        }
        else {
            
            // Have to clear cookies - grrr
            let cookieStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
            if let cookies = cookieStorage.cookiesForURL(url!) {
                for cookie in cookies {
                    cookieStorage.deleteCookie(cookie )
                }
            }
        }
        
        /* Start the request! */
        connection = NSURLConnection(request: urlRequest, delegate: self)
        
    }
    
    func done() {
        
        if !NSThread.isMainThread() {
            
            dispatch_async(dispatch_get_main_queue(), {
                self.logger.log(.DEBUG, message: "Completing service operation on main thread")
                self.done()
            })
            return;
        }
        
        if connection != nil {
            connection!.cancel()
            connection = nil
        }
        
        self.willChangeValueForKey("isExecuting")
        self.willChangeValueForKey("isFinished")
        _executing = false
        _finished = true
        self.didChangeValueForKey("isExecuting")
        self.didChangeValueForKey("isFinished")
        
    }
    
    func doCancel() {
        
        error = NSError(domain: "DownloadUrlOperation", code: 123, userInfo: nil)
        self.done()
    }
    
    /* OVerride Functions and variables where needed */
    
    override var executing : Bool {
        get { return _executing }
        set { _executing = newValue }
    }
    var _executing : Bool
    
    override var finished : Bool {
        get { return _finished }
        set { _finished = newValue }
    }
    var _finished : Bool
    
    override var concurrent : Bool {
        get { return _concurrent }
        set { _concurrent = newValue }
    }
    
    var _concurrent : Bool
    
    /*
    func isConcurrent() -> Bool {
        return true;
    }
    
    func isExecuting() -> Bool {
        return _executing
    }
    
    func isFinished() -> Bool {
        return _finished
    }
    */
    
    // MARK: NSURLConnection delegate methods
    
    func connection(connection: NSURLConnection, didFailWithError error: NSError) {
        
        if self.cancelled {
            self.doCancel()
        }
        else {
            self.error = error;
            self.done()
        }
    }
    
    func connection(connection: NSURLConnection!, didReceiveResponse response: NSURLResponse!) {
        
        if self.cancelled {
            self.doCancel()
            return
        }
        
        /* How are we looking? */
        let httpResponse = response as! NSHTTPURLResponse
        statusCode = httpResponse.statusCode
        
        if statusCode == 200 || statusCode == 201 {
            
            let contentSize = httpResponse.expectedContentLength > 0 ? httpResponse.expectedContentLength : 0
            returnData = NSMutableData(capacity: Int(contentSize))
            
        }
        else {
            
            let statusError = "HTTP Error \(statusCode)"
            let userInfo = NSDictionary(object: statusError, forKey: NSLocalizedDescriptionKey)
            error = NSError(domain: "DownloadUrlOperation", code: statusCode, userInfo: userInfo as [NSObject : AnyObject])
            
            logger.log(.WARN, message: statusError)
            
            self.done()
        }
    }
    
    func connection(connection: NSURLConnection!, didReceiveData data: NSData!) {
        
        if self.cancelled {
            self.doCancel()
            return
        }
        
        self.returnData?.appendData(data)
        
    }
    
    /* We are done! */
    func connectionDidFinishLoading(connection: NSURLConnection) {
        
        if self.cancelled {
            self.doCancel()
            return
        }
        logger.log(.DEBUG, message: "finishing service connection for \(url!)")
        self.done()
    }
    
}


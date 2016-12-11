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

class AuthMeServiceOperation: Operation, NSURLConnectionDelegate {
    
    var logger = Log()
    
    let serviceIdentifier = "readercom.com"
    let usernameKey = "serviceUsername"
    
    var url: URL? = nil
    var connection: NSURLConnection? = nil
    
    var returnData: NSMutableData? = nil
    var postData: Data? = nil
    var error: NSError? = nil
    var secureRequest = false
    var statusCode: Int = 0
    
    /* Actually an opaque type to this guy */
    var operationType = AuthMeService.AuthMeOperationType.unknownOperation
    var opaqueData: AnyObject? = nil
    var delegate: AuthMeServiceDelegate? = nil
    
    init(url: NSString) {
        
        self.url = URL(string: url as String)
        _executing = false;
        _finished = false;
        _concurrent = true;
        
    }
    
    override
    func start() {
        
        
        if !Thread.isMainThread {
            
            DispatchQueue.main.async(execute: {
                
                self.start()
            })
            return;
        }
        
        if url == nil {
            logger.log(.error, message: "Error in ReadercomServiceOperation - URL not defined")
            return
        }
        
        self.willChangeValue(forKey: "isExecuting")
        self.isExecuting = true
        self.didChangeValue(forKey: "isExecuting")
        
        logger.log(.debug, message: "Starting service thread for \(url)")
        
        /* Now kick off the connection! */
        let urlRequest = NSMutableURLRequest(url: url!)
        
        /* For a post - add the right headers and the data to the request */
        if let toPost = postData {
            urlRequest.httpMethod = "PUT"
            let postLength = String(toPost.count)
            urlRequest.setValue(postLength, forHTTPHeaderField: "Content-Length")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.httpBody = toPost
        }
        
        if secureRequest == true {
            
            let appConfiguration = AppConfiguration.getInstance()
            
            // Need to add username and password
            if let username = appConfiguration.getConfigItem(usernameKey as NSString) as? String {
                if username != ""  { //appConfiguration.getConfigItem(usernameKey) as? String {
                    let usernamePassword = username + ":" + appConfiguration.getServicePassword()
                
                    if let raw = usernamePassword.data(using: String.Encoding.utf8, allowLossyConversion: false) {
                        let base64 = raw.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength64Characters)
                    
                        // Add to headers
                        let fullHeader = "Basic " + base64
                        urlRequest.setValue(fullHeader, forHTTPHeaderField: "Authorization")
                    }
                }
            }
        }
        else {
            
            // Have to clear cookies - grrr
            let cookieStorage = HTTPCookieStorage.shared
            if let cookies = cookieStorage.cookies(for: url!) {
                for cookie in cookies {
                    cookieStorage.deleteCookie(cookie )
                }
            }
        }
        
        /* Start the request! */
        connection = NSURLConnection(request: urlRequest as URLRequest, delegate: self)
        
    }
    
    func done() {
        
        if !Thread.isMainThread {
            
            DispatchQueue.main.async(execute: {
                self.logger.log(.debug, message: "Completing service operation on main thread")
                self.done()
            })
            return;
        }
        
        if connection != nil {
            connection!.cancel()
            connection = nil
        }
        
        self.willChangeValue(forKey: "isExecuting")
        self.willChangeValue(forKey: "isFinished")
        _executing = false
        _finished = true
        self.didChangeValue(forKey: "isExecuting")
        self.didChangeValue(forKey: "isFinished")
        
    }
    
    func doCancel() {
        
        error = NSError(domain: "DownloadUrlOperation", code: 123, userInfo: nil)
        self.done()
    }
    
    /* OVerride Functions and variables where needed */
    
    override var isExecuting : Bool {
        get { return _executing }
        set { _executing = newValue }
    }
    var _executing : Bool
    
    override var isFinished : Bool {
        get { return _finished }
        set { _finished = newValue }
    }
    var _finished : Bool
    
    override var isConcurrent : Bool {
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
    
    func connection(_ connection: NSURLConnection, didFailWithError error: Error) {
        
        if self.isCancelled {
            self.doCancel()
        }
        else {
            self.error = error as NSError?;
            self.done()
        }
    }
    
    func connection(_ connection: NSURLConnection!, didReceiveResponse response: URLResponse!) {
        
        if self.isCancelled {
            self.doCancel()
            return
        }
        
        /* How are we looking? */
        let httpResponse = response as! HTTPURLResponse
        statusCode = httpResponse.statusCode
        
        if statusCode == 200 || statusCode == 201 {
            
            let contentSize = httpResponse.expectedContentLength > 0 ? httpResponse.expectedContentLength : 0
            returnData = NSMutableData(capacity: Int(contentSize))
            
        }
        else {
            
            let statusError = "HTTP Error \(statusCode)"
            let userInfo = NSDictionary(object: statusError, forKey: NSLocalizedDescriptionKey as NSCopying)
            error = NSError(domain: "DownloadUrlOperation", code: statusCode, userInfo: userInfo as! [AnyHashable: Any])
            
            logger.log(.warn, message: statusError)
            
            self.done()
        }
    }
    
    func connection(_ connection: NSURLConnection!, didReceiveData data: Data!) {
        
        if self.isCancelled {
            self.doCancel()
            return
        }
        
        self.returnData?.append(data)
        
    }
    
    /* We are done! */
    func connectionDidFinishLoading(_ connection: NSURLConnection) {
        
        if self.isCancelled {
            self.doCancel()
            return
        }
        logger.log(.debug, message: "finishing service connection for \(url!)")
        self.done()
    }
    
}


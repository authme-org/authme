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
//  Log.swift
//
//  Created by Berin Lautenbach on 1/01/2015.
//  Copyright (c) 2015 Berin Lautenbach. All rights reserved.
//

import Foundation

/* Simple class to handle logging for us */

var currentLoggingLevel = Log.Level.info

class Log {
    
    enum Level: Int {
        case finest = 0
        case fine
        case debug
        case info
        case warn
        case error
        case die
    }
    
    var LevelStrings = ["FINEST", "FINE", "DEBUG", "INFO", "WARN", "ERROR", "DIE"]
    var filename: String
    
    // MARK: Initialisation
    init(filename: String = #file) {
        
        /* First strip the filename */
        if let fileRange = filename.range(of: "/", options: NSString.CompareOptions.backwards, range: nil, locale: nil) {
            if !fileRange.isEmpty {
                self.filename = String(filename[fileRange.upperBound...])
            }
            else {
                self.filename = filename
            }
        }
        else {
            self.filename = filename
        }
    }
    
    func log(_ level: Level,
        message: String,
        function: String = #function,
        line: Int = #line) {
            
            if level.rawValue >= currentLoggingLevel.rawValue {
            
                /* If we are going to log - do it only on the main thread */
                
                if !Thread.isMainThread {
                    
                    DispatchQueue.main.async(execute: {
                        
                        self.log(level, message: message, function: function, line: line)
                        
                    })
                    return;
                }
                
                print("\(LevelStrings[level.rawValue]) \(filename):\(line)(\(function)) \(message)")
            }
            
    }
    
    // TODO: Make this threadsafe - but this'll do for now as we only call once
    class func setLogLevel(_ level: Level) {
        currentLoggingLevel = level
    }
    
    class func getLogLevel() -> Level {
        return currentLoggingLevel
    }
    
}

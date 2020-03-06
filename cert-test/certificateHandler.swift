//
//  certificateHandler.swift
//  cert-test
//
//  Created by Oscar Fredriksson on 2020-03-04.
//  Copyright © 2020 Oscar Fredriksson. All rights reserved.
//

import Foundation

struct CertificateHandler
{
    private struct IdentityAndTrust {

        public var identityRef:SecIdentity
        public var trust:SecTrust
        public var certArray:NSArray
    }

    public static func getClientURLCredential(base64CertData: String, certPassword: String)->URLCredential
    {
        let localCertData: NSData = NSData(base64Encoded: base64CertData, options: .ignoreUnknownCharacters)!
        
        let userIdentityAndTrust = extractIdentity(certData: localCertData as NSData, certPassword: certPassword)
        //Create URLCredential
                    
        let urlCredential = URLCredential(identity: userIdentityAndTrust.identityRef,
                                      certificates: userIdentityAndTrust.certArray as [AnyObject],
                                      persistence: URLCredential.Persistence.permanent)

        return urlCredential;        
    }
    
    
    /*
        Extract certificate to a URLCredential-object from a given filename + extension and password.
        The URLCredential-object is what is used in the URLChallange when establishing the websocket or HTTPS connection.
     */
    public static func getClientUrlCredential(certName: String, certExtension: String, certPassword: String)->URLCredential
    {
        let DocumentDirURL = try! FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        
        let fileURL = DocumentDirURL.appendingPathComponent(certName).appendingPathExtension("pfx")

        //Read content of pfx-file
        let certData = NSData(contentsOf: fileURL);
                
        //Extract certificates from pfx-data
        let userIdentityAndTrust = extractIdentity(certData: certData!, certPassword: certPassword)
                
        //Create URLCredential
        let urlCredential = URLCredential(  identity: userIdentityAndTrust.identityRef,
                                            certificates: userIdentityAndTrust.certArray as [AnyObject],
                                            persistence: URLCredential.Persistence.permanent)
            
        return urlCredential
    }

    private static func extractIdentity(certData:NSData, certPassword:String) -> IdentityAndTrust {

        var identityAndTrust:IdentityAndTrust!
        var securityError:OSStatus = errSecSuccess

        var items: CFArray?
        let certOptions: Dictionary = [ kSecImportExportPassphrase as String : certPassword ];
        
        // import certificate to read its entries
        securityError = SecPKCS12Import(certData, certOptions as CFDictionary, &items);
        if securityError == errSecSuccess {

            //Print all the certificates
            //let itemsArray = items as CFArray?;
            //print(itemsArray)
            
            let certItems:CFArray = (items as CFArray?)!;
            let certItemsArray:Array = certItems as Array
                
            let dict:AnyObject? = certItemsArray.first;

            if let certEntry:Dictionary = dict as? Dictionary<String, AnyObject> {

                // grab the identity
                let identityPointer:AnyObject = certEntry["identity"]!;
                let secIdentityRef:SecIdentity = identityPointer as! SecIdentity;

                // grab the trust
                let trustPointer:AnyObject = certEntry["trust"]!;
                let trustRef:SecTrust = trustPointer as! SecTrust;

                //Array with all certificates
                let certArray:NSMutableArray = NSMutableArray();
                
                let certEntryList:NSArray = certEntry["chain"] as! NSArray;

                for cert in certEntryList
                {
                    certArray.add(cert as! SecCertificate);
                }
                
                //print(certArray);
                
                identityAndTrust = IdentityAndTrust(identityRef: secIdentityRef, trust: trustRef, certArray: certArray);
            }
        }

        return identityAndTrust;
    }
}

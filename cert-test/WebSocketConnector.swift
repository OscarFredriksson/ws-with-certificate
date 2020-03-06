//
//  WebSocketConnector.swift
//  cert-test
//
//  Created by Oscar Fredriksson on 2020-03-02.
//  Copyright © 2020 Oscar Fredriksson. All rights reserved.
//

import Foundation
class WebSocketConnector : NSObject {
    
    var didReceiveMessage : ((_ message : String)->())?
    
    var urlSession : URLSession!
    var operationQueue : OperationQueue = OperationQueue()
    var socket : URLSessionWebSocketTask!
        
    var urlString : String!
    var urlPort : String!
    
    var certName : String!
    var certExtension : String!
    var certPassword : String!
            
    init(urlString: String, portString: String)//withSocketURL url : URL)
    {
        super.init()
                
        let url: URL = URL(string: "wss://" + urlString + ":" + portString)!;
        
        urlSession  = URLSession(configuration: .default, delegate: self, delegateQueue: operationQueue)
        socket = urlSession.webSocketTask(with: url);
        
        self.urlString = urlString;
    }
    
    
    /*
     
     */
    func setCertificate(certName: String, certExtension: String, certPassword: String)
    {
        self.certName = certName;
        self.certExtension = certExtension;
        self.certPassword = certPassword;
    }
    
    func establishConnection(){
                
        let message = "connecting...\n";
        
        self.didReceiveMessage!(message);
        
        socket.resume();
    }
    
    func disconnect() {
        socket.cancel(with: .goingAway, reason: nil)
    }
    
    func sendMessage(message: String)
    {
        let message = URLSessionWebSocketTask.Message.string(message);
        
        socket.send(message) { error in
            if let error = error {
                self.didReceiveMessage!("WebSocket sending error: \(error)")
            }
        }

        //Wait for response:
        readMessage();
    }
    
    func readMessage()  {
        socket.receive { result in
            switch result {
            case .failure(let error):
                self.didReceiveMessage!("Failed to receive message: \(error)")
            case .success(let message):
                switch message {
                case .string(let text):
                    self.didReceiveMessage!("Received text message: \(text)")
                case .data(let data):
                    self.didReceiveMessage!("Received binary message: \(data)")
                @unknown default:
                    fatalError()
                }
                
                //Keep listening for more messages
                self.readMessage()
            }
        }
    }
}

extension WebSocketConnector : URLSessionWebSocketDelegate
{
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,didOpenWithProtocol protocol: String?)
    {
        self.didReceiveMessage!("connected")
    };
    
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
    {
        self.didReceiveMessage!("disconnected");
    };
}

extension WebSocketConnector : URLSessionDelegate
{
    /*
        When connecting to the server it will send an authentication challenge back which is caught and run by this function.
     
        The function first receives the challenge NSURLAuthenticationMethodServerTrust where it just checks the host url. Then it receives the challenge NSURLAuthenticationMethodClientCertificate where it sends back the client certificate to the server.
     */
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
        {
            let authenticationMethod = challenge.protectionSpace.authenticationMethod
            
    //        print("authenticationMethod=\(authenticationMethod)")

            if authenticationMethod == NSURLAuthenticationMethodServerTrust
            {
                let protectionSpace = challenge.protectionSpace
                guard protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                    protectionSpace.host.contains(self.urlString) else  //Trust the given host url
                {
                    //.performDefaultHandling rejects the connection
                    completionHandler(.performDefaultHandling, nil)
                    return
                }
                
                guard let serverTrust = protectionSpace.serverTrust else {
                    completionHandler(.performDefaultHandling, nil)
                    return
                }
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
            }
            else if authenticationMethod == NSURLAuthenticationMethodClientCertificate
            {
                //Get the client certificate as a URLCredential object
                let clientCred = CertificateHandler.getClientUrlCredential(
                                                        certName: self.certName,
                                                        certExtension: self.certExtension,
                                                        certPassword: self.certPassword);
                
                completionHandler(.useCredential, clientCred)
            }
        }
}

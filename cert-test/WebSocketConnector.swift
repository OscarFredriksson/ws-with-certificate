//
//  WebSocketConnector.swift
//  cert-test
//
//  Created by Oscar Fredriksson on 2020-03-02.
//  Copyright © 2020 Oscar Fredriksson. All rights reserved.
//

import Foundation
class WebSocketConnector : NSObject {
    
    var didOpenConnection : (()->())?
    var didCloseConnection : (()->())?
    var didReceiveMessage : ((_ message : String)->())?
    var didReceiveData : ((_ message : Data)->())?
    //var didReceiveError : ((_ error : Error)->())?
    
    var urlSession : URLSession!
    var operationQueue : OperationQueue = OperationQueue()
    var socket : URLSessionWebSocketTask!
        
    var urlString : String!
    var urlPort : String!
    
    var certName : String!
    var certExtension : String!
    var certPassword : String!
    
    var base64CertData: String!
        
    init(urlString: String, portString: String)//withSocketURL url : URL)
    {
        super.init()
                
        let url: URL = URL(string: "wss://" + urlString + ":" + portString)!;
        
        urlSession  = URLSession(configuration: .default, delegate: self, delegateQueue: operationQueue)
        socket = urlSession.webSocketTask(with: url);
        
        self.urlString = urlString;
    }
    
    func setCertificate(certName: String, certExtension: String, certPassword: String)
    {
        self.certName = certName;
        self.certExtension = certExtension;
        self.certPassword = certPassword;
    }
    
    func setCertificate(base64CertString: String, certPassword: String)
    {
        self.base64CertData = base64CertString;
        self.certPassword = certPassword;
    }
    
    func establishConnection(){
                
        let message = "connecting...\n";
        
        print(message);
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
                print("WebSocket sending error: \(error)")
            }
        }

        //Wait for response:
        readMessage();
    }
    
    func readMessage()  {
        socket.receive { result in
            switch result {
            case .failure(let error):
                print("Failed to receive message: \(error)")
                self.didReceiveMessage!("Failed to receive message: \(error)")
            case .success(let message):
                switch message {
                case .string(let text):
                    print("Received text message: \(text)")
                    self.didReceiveMessage!("Received text message: \(text)")
                case .data(let data):
                    print("Received binary message: \(data)")
                    self.didReceiveMessage!("Received binary message: \(data)")
                @unknown default:
                    fatalError()
                }
                
                self.readMessage()
            }
        }
    }
}

extension WebSocketConnector : URLSessionWebSocketDelegate
{
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,didOpenWithProtocol protocol: String?)
    {
        print("connected");
        self.didReceiveMessage!("connected")
    };
    
    /*func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
    {
        print("disconnected");
        self.outputLabel.text = "disconnected\n";
    };*/
}

extension WebSocketConnector : URLSessionDelegate
{
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
        {
            let authenticationMethod = challenge.protectionSpace.authenticationMethod
    //        print("authenticationMethod=\(authenticationMethod)")

            if authenticationMethod == NSURLAuthenticationMethodClientCertificate {
                                
                let clientCred = CertificateHandler.getClientUrlCredential(
                                                        certName: self.certName,
                                                        certExtension: self.certExtension,
                                                        certPassword: self.certPassword);
//
//                let clientCred = CertificateHandler.getClientURLCrednetial(base64CertData: self.base64CertData, certPassword: self.certPassword);
                
                completionHandler(.useCredential, clientCred)

            } else if authenticationMethod == NSURLAuthenticationMethodServerTrust {
                
                let protectionSpace = challenge.protectionSpace
                guard protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                    protectionSpace.host.contains(self.urlString) else {
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
        }
}

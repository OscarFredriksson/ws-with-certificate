//
//  ViewController.swift
//  cert-test
//
//  Created by Oscar Fredriksson on 2020-02-14.
//  Copyright © 2020 Oscar Fredriksson. All rights reserved.
//

import UIKit


class ViewController: UIViewController {
    
    //Chair IP: 192.168.8.1:7441
    var socket = WebSocketConnector(urlString: "192.168.8.1", portString: "7441");
    
    var base64CertString: String!
    
    override func viewDidLoad()
    {
        super.viewDidLoad()
                
        self.socket.didReceiveMessage = { message in
            DispatchQueue.main.async
            {
                print(message);
                self.outputLabel.text = message;
            }
        }
    }
    
    @IBOutlet weak var outputLabel: UILabel!
    
    @IBAction func getCert(_ sender: Any)
    {
        struct Base64Cert: Decodable
        {
            let cert: String;
        };
        
        //Get certificate from local server
        let url = URL(string: "http://localhost:3000/cert")!
        
        let task = URLSession.shared.dataTask(with: url) {(data, response, error) in
            guard let data = data else { return }
            
            print("Got a certificate from server\n");
            
            let base64Cert: Base64Cert = try! JSONDecoder().decode(Base64Cert.self, from: data)
            
            let filename = "created_cert"
            let DocumentDirURL = try! FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)

            let fileURL = DocumentDirURL.appendingPathComponent(filename).appendingPathExtension("pfx")

            let decodedData = Data(base64Encoded: base64Cert.cert)!

            do {
                try decodedData.write(to: fileURL, options: .atomic);
                print("Cert saved to: " + NSHomeDirectory() + "/Documents/" + filename + ".pfx");
            } catch {
                print("failed with error: \(error)")
            }
        }

        task.resume()
    }
    
    @IBAction func websocketConnect(_ sender: Any)
    {

        DispatchQueue.main.async
        {
            self.socket.setCertificate(certName: "created_cert", certExtension: "pfx", certPassword: "test")
            self.socket.establishConnection();
        }
    }
    
    @IBAction func websocketSend(_ sender: Any)
    {
        socket.sendMessage(message: "POST api/v1/echo/test\r\n" +
                                    "Content-Type: application/json\r\n" +
                                    "Content-Length: 12\r\n" +
                                    "Message-Identifier: 00000000-1111-2222-3333-444455556666\r\n" +
                                    "\r\n" +
                                    "Hello World!");

//        socket.sendMessage(message: "ping");
    }
}

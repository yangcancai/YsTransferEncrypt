﻿# YsTransferEncrypt
RSA 
```java
 String filenameprivatekey = "rsa_private_key.pem";
           String filenamepublickey = "rsa_public_key.pem";
           StreamReader sr = File.OpenText(filenameprivatekey);
           String pemstrPrivate = sr.ReadToEnd().Trim();
           sr = File.OpenText(filenamepublickey);
           String pemstrPublic = sr.ReadToEnd().Trim();
           string msg = "hello world";
           string sekey = Convert.ToBase64String(JavaScience.opensslkey.DecodeOpenSSLPrivateKey(pemstrPrivate));
           string pubkey = Convert.ToBase64String(JavaScience.opensslkey.DecodeOpenSSLPublicKey(pemstrPublic));
           RSACryptoServiceProvider rsa = JavaScience.opensslkey.DecodeX509PublicKey(JavaScience.opensslkey.DecodeOpenSSLPublicKey(pemstrPublic));
           String xmlpublickey = rsa.ToXmlString(false);
           RSACryptoServiceProvider rsa1 = JavaScience.opensslkey.DecodeRSAPrivateKey(JavaScience.opensslkey.DecodeOpenSSLPrivateKey(pemstrPrivate));
           String xmlprivatekey = rsa1.ToXmlString(true);
           string encode_msg = RSAHelper.RSAEncrypt(xmlpublickey, msg);
           string decode_msg = RSAHelper.RSADecrypt(xmlprivatekey, encode_msg);
           Debug.WriteLine("decode_msg:" + decode_msg);
           Debug.WriteLine("encode_msg:" + encode_msg);
           Assert.IsTrue(msg == decode_msg);
```

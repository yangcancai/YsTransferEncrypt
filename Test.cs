using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace YsTransferEncrypt
{
  public class Test
    {
       public static void TestHttp()
       {
           // AES helper test
          // string kk = AESHelper.AESEncrypt("Test String", "1234567812345678", "1234567812345678");
          // String filenameprivatekey = "rsa_private_key.pem";
          // String filenamepublickey = "rsa_public_key.pem";
          // StreamReader sr = File.OpenText(filenameprivatekey);
          // String pemstrPrivate = sr.ReadToEnd().Trim();
          // sr = File.OpenText(filenamepublickey);
          // String pemstrPublic = sr.ReadToEnd().Trim();
         
          // //if (pemprivatekey != null)
          // //{

          // //    JavaScience.opensslkey.showBytes("\nRSA private key", pemprivatekey);
          // //    //PutFileBytes("rsaprivkey.pem", pemprivatekey, pemprivatekey.Length) ;
          // //    RSACryptoServiceProvider rsa = JavaScience.opensslkey.DecodeRSAPrivateKey(pemprivatekey);
          // //    Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n");
          // //    String xmlprivatekey = rsa.ToString();
          // //    Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, Convert.ToBase64String(pemprivatekey));
          // //}
          // string msg = "kdfjkdjfkdfdf" + CryptHelper.MD5(CryptHelper.ConvertDateTimeInt(System.DateTime.Now).ToString()) + CryptHelper.MD5(CryptHelper.ConvertDateTimeInt(System.DateTime.Now).ToString());
          // msg = "72fa43c4d76bb2cced0853959d8864cc72fa43c4d76bb";
          // string token = "SbHtRC2GTvaldiNJ";
          // string key = "SbHtRC2GTvaldiNJ";
          // string encode_msg = AESHelper.AESEncrypt(msg,key,key);
          // string decode_msg = AESHelper.AESDecrypt("ZOHN1O/zLhb6W5fFzG0h3bDKh1lV2EF4DYj3Hl/f/4NkTIZ0JiH07/s2yNlnsus5VfIoLeIaUP0YbIWNY4wlwg==",key,key);
          //  encode_msg = CryptHelper.Encode(msg,token,key,EncryptType.IsAES,"0");
          //  decode_msg = CryptHelper.Decode(encode_msg,token,key,EncryptType.IsAES);
          // //check AES decode and encode 
          // Assert.IsTrue(msg == decode_msg);
          // string pubkey;
          // string sekey;
          // RSAHelper.GetRSAKey(out sekey, out pubkey);
          // RSAHelper.RSAKey keyPair = RSAHelper.GetRASKey();
          // //pubkey = keyPair.PublicKey;
          //// sekey = keyPair.PrivateKey;
          
          // // publickey encode and privatekey decode
          // encode_msg = CryptHelper.Encode(msg, pubkey, pubkey, EncryptType.IsRSA, "0");
          // decode_msg = CryptHelper.Decode(encode_msg, pubkey, sekey, EncryptType.IsRSA);
          // Assert.IsTrue(msg==decode_msg);
        
          // // only plaintext,no encryption algorithm
          // encode_msg = CryptHelper.Encode(msg, token, key, EncryptType.NON, "0");
          // decode_msg = CryptHelper.Decode(encode_msg, token, key, EncryptType.NON);
          // Assert.IsTrue(msg == decode_msg);
          // sekey = Convert.ToBase64String(JavaScience.opensslkey.DecodeOpenSSLPrivateKey(pemstrPrivate));
          // pubkey = Convert.ToBase64String(JavaScience.opensslkey.DecodeOpenSSLPublicKey(pemstrPublic));
          // RSACryptoServiceProvider rsa = JavaScience.opensslkey.DecodeX509PublicKey(JavaScience.opensslkey.DecodeOpenSSLPublicKey(pemstrPublic));
          // String xmlpublickey = rsa.ToXmlString(false);
          //RSACryptoServiceProvider  rsa1 = JavaScience.opensslkey.DecodeRSAPrivateKey(JavaScience.opensslkey.DecodeOpenSSLPrivateKey(pemstrPrivate));
          //String xmlprivatekey = rsa1.ToXmlString(true);
          // encode_msg = RSAHelper.RSAEncrypt(xmlpublickey, msg);
          // decode_msg = RSAHelper.RSADecrypt(xmlprivatekey, encode_msg);
          // Debug.WriteLine("decode_msg:"+decode_msg);
          // Debug.WriteLine("encode_msg:"+encode_msg);
          // Assert.IsTrue(msg == decode_msg);
           StringBuilder url = new StringBuilder();
           string compress = "{\"entry_account\":\"root\",\"md5\":\"3D4747F06E6FA59751B9E09445410769\",\"actionid\":\"7\",\"accountcode\":\"\",\"type\":\"Time\",\"req_parameter\":\"2015-1-1 00:00:00|2017-1-1 00:00:00|2|1000\"}";
           string key = "SbHtRC2GTvaldiNJ";
           string vi = key;
            string req = CryptHelper.Encode(compress, key,vi, EncryptType.IsAES, "1");
            url.AppendFormat("http://192.168.1.105/Lobby/new/psg_rcm/entry.php?{0}",req);
           string encode_msg = YsGames.Framework.Account.HttReq.Post(url.ToString());
           string decode_msg =  CryptHelper.Decode(encode_msg,key,vi);
          //string encode_msg = AESHelper.AESEncrypt(compress, "SbHtRC2GTvaldiNJ", "SbHtRC2GTvaldiNJ");
          //string decode_msg = AESHelper.AESDecrypt(encode_msg, "SbHtRC2GTvaldiNJ", "SbHtRC2GTvaldiNJ");
          //Assert.IsTrue(decode_msg==compress);
       }
    }
}

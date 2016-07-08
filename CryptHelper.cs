using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace YsTransferEncrypt
{
//    协议格式
//Request: 
//compress=Base64(EncryptFun(Data）
//&id=IdValue
//&sign=SignValue
//&timestamp=TimeStampValue
//&msign=MsignValue
//&encrypt=IsAES|IsRSA|false

//Response:
//compress=Base64(EncryptFun(Data）
//&msign=MsignValue
//&sign=SignValue
//&timestamp=TimeStampValue
//&encrypt=IsAES|IsRSA|false
//&resp_id=
// 签名
//Msign=MD5（ASCII字典升序(compress=Compress&aes_key=AESKey)）.ToUpper().
//Sign=SHA1(ASCII字典升序(token=Token&msign=Msign&timestamp=TimeStamp)).
//Response：
//Msign=MD5（ASCII字典升序(compress=Compress&aes_key=AESKey)）.ToUpper().
//Sign=SHA1(ASCII字典升序(token=Token&msign=Msign&timestamp=TimeStamp)).
   public enum EncryptType
   {
       IsAES,
       IsRSA,
       NON
   }
   public class CryptHelper
    {
        /// <summary>  
        /// 时间戳转为C#格式时间  
        /// </summary>  
        /// <param name="timeStamp">Unix时间戳格式</param>  
        /// <returns>C#格式时间</returns>  
        public static DateTime GetTime(string timeStamp)
        {
            DateTime dtStart = TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1));
            long lTime = long.Parse(timeStamp + "0000000");
            TimeSpan toNow = new TimeSpan(lTime);
            return dtStart.Add(toNow);
        }  
  
        /// <summary>  
        /// DateTime时间格式转换为Unix时间戳格式  
        /// </summary>  
        /// <param name="time"> DateTime时间格式</param>  
        /// <returns>Unix时间戳格式</returns>  
        public static int ConvertDateTimeInt(System.DateTime time)
        {
            System.DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1));
            return (int)(time - startTime).TotalSeconds;
        }  
       public static string MD5(string sDataIn)
       {
           MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
           byte[] bytValue, bytHash;
           bytValue = System.Text.Encoding.UTF8.GetBytes(sDataIn);
           bytHash = md5.ComputeHash(bytValue);
           md5.Clear();
           string sTemp = "";
           for (int i = 0; i < bytHash.Length; i++)
           {
               sTemp += bytHash[i].ToString("X").PadLeft(2, '0');
           }
           return sTemp.ToLower();
       }
       public static string sha1(string msg)
       {
           SHA1 sha1 = new SHA1CryptoServiceProvider();
           byte[] bytes_old_string = UTF8Encoding.Default.GetBytes(msg);
           byte[] bytes_new_string = sha1.ComputeHash(bytes_old_string);
           string new_string = BitConverter.ToString(bytes_new_string);
           new_string = new_string.Replace("-", "").ToUpper();
           return new_string;
       }
       /// <summary>
       /// MD5签名
       /// </summary>
       /// <param name="key"></param>
       /// <param name="msg"></param>
       /// <returns></returns>
       public static string MD5Sign(string key, string msg)
       {
           StringBuilder s = new StringBuilder();
           s.AppendFormat("aes_key={0}&compress={1}", key, msg);
           return MD5(s.ToString()).ToUpper();
       }
       /// <summary>
       /// sha1签名
       /// </summary>
       /// <param name="msign"></param>
       /// <param name="timestamp"></param>
       /// <param name="token"></param>
       /// <returns></returns>
       public static string SHA1Sign(string msign,string timestamp,string token)
       {
           StringBuilder s = new StringBuilder();
           s.AppendFormat("msign={0}&timestamp={1}&token={2}", msign, timestamp, token);
           return sha1(s.ToString());
       }
       /// <summary>
       /// 
       /// </summary>
       /// <param name="msg">数据明文</param>
       /// <param name="token">sha1签名使用的token</param>
       /// <param name="key">aes_key或rsa 秘钥或rsa公钥</param>
       /// <param name="crypttype">加密算法</param>
       /// <param name="id">接入商id或唯一md5字符串</param>
       /// <returns>null 加密异常 或 加密密文</returns>
       public static string Encode(string msg,string token,string key, EncryptType crypttype,string id)
       {
           try
           {
               string encode_msg = msg;
               if (crypttype == EncryptType.IsAES)
               {
                   encode_msg = AESHelper.Base64ToBase64Url(AESHelper.AESEncrypt(msg, key,key));
               }
               else if (crypttype == EncryptType.IsRSA)
               {
                   encode_msg = AESHelper.Base64ToBase64Url(RSAHelper.RSAEncrypt(key, msg));
               }
               StringBuilder s = new StringBuilder();
               string timestamp = ConvertDateTimeInt(DateTime.Now).ToString();
               string msign = MD5Sign(crypttype==EncryptType.IsRSA?token:key, encode_msg);
               string sign = SHA1Sign(msign, timestamp, token);
               s.AppendFormat("compress={0}&id={1}&sign={2}&timestamp={3}&msign={4}&encrypt={5}", encode_msg, id, sign, timestamp, msign,crypttype.ToString());
               return s.ToString();
           }catch(Exception e)
           {
               return null;
           }
       }
       /// <summary>
       /// 
       /// </summary>
       /// <param name="msg">密文</param>
       /// <param name="token">sha1签名key</param>
       /// <param name="key">aeskey或rsa公钥或rsa密钥</param>
       /// <param name="crypttype">加密算法</param>
       /// <returns>null或明文</returns>
       public static string Decode(string msg, string token, string key)
       {
           try
           {
               string[] key_val = msg.Split('&');
               Dictionary<string, string> dictKeyVal = new Dictionary<string, string>();
               for (int i = 0; i < key_val.Length; i++)
               {
                   string[] s = key_val[i].Split('=');
                   if (dictKeyVal.ContainsKey(s[0]) == false)
                       dictKeyVal.Add(s[0], s[1]);
               }
               string sign = SHA1Sign(dictKeyVal["msign"], dictKeyVal["timestamp"], token);
               string msign = MD5Sign(dictKeyVal["encrypt"] == "IsRSA" ? token : key, dictKeyVal["compress"]);
               if (sign == dictKeyVal["sign"] && msign == dictKeyVal["msign"])
               {
                   string decode_msg = dictKeyVal["compress"];
                   if (dictKeyVal["encrypt"] == EncryptType.IsRSA.ToString())
                   {
                       decode_msg = RSAHelper.RSADecrypt(key, AESHelper.Base64UrlToBase64(dictKeyVal["compress"]));
                   }
                   else if (dictKeyVal["encrypt"] == EncryptType.IsAES.ToString())
                   {
                       decode_msg = AESHelper.AESDecrypt(AESHelper.Base64UrlToBase64(decode_msg),key,key);
                   }
                   return decode_msg;
               }
               else
               {
                   return null;
               }
           }catch(Exception e)
           {
               return null;
           }
       }
    }
}

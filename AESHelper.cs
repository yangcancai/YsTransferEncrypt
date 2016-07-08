using System.Linq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace YsTransferEncrypt
{
  public  class AESHelper
    {
        /// <summary>
        /// 密钥  暂时写死
        /// </summary>
        public static string Key = "SbHtRC2GTvaldiNJMBs8YAVVi0DTBfHX";

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static String Encrypt(String Data)
        {
           return  AESEncrypt(Data, Key);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static String Decrypt(String Data)
        {
            return AESDecrypt(Data, Key);
        }
        /// <summary>
        /// AES加密(无向量)
        /// </summary>
        /// <param name="plainBytes">被加密的明文</param>
        /// <param name="key">密钥</param>
        /// <returns>密文</returns>
        public static string AESEncrypt(String Data, String Key)
        {
            MemoryStream mStream = new MemoryStream();
            RijndaelManaged aes = new RijndaelManaged();

            byte[] plainBytes = Encoding.UTF8.GetBytes(Data);
            Byte[] bKey = new Byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(Key.PadRight(bKey.Length)), bKey, bKey.Length);

            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;
            //aes.Key = _key;
            aes.Key = bKey;
            //aes.IV = _iV;
            CryptoStream cryptoStream = new CryptoStream(mStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            try
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                cryptoStream.FlushFinalBlock();
                return Convert.ToBase64String(mStream.ToArray());
            }
            finally
            {
                cryptoStream.Close();
                mStream.Close();
                aes.Clear();
            }
        }


        /// <summary>
        /// AES解密(无向量)
        /// </summary>
        /// <param name="encryptedBytes">被加密的明文</param>
        /// <param name="key">密钥</param>
        /// <returns>明文</returns>
        public static string AESDecrypt(String Data, String Key)
        {
            Byte[] encryptedBytes = Convert.FromBase64String(Data);
            Byte[] bKey = new Byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(Key.PadRight(bKey.Length)), bKey, bKey.Length);
            
            MemoryStream mStream = new MemoryStream(encryptedBytes);
            //mStream.Write( encryptedBytes, 0, encryptedBytes.Length );
            //mStream.Seek( 0, SeekOrigin.Begin );
            RijndaelManaged aes = new RijndaelManaged();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;
            aes.Key = bKey;
            //aes.IV = _iV;
            CryptoStream cryptoStream = new CryptoStream(mStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            try
            {
                byte[] tmp = new byte[encryptedBytes.Length + 32];
                int len = cryptoStream.Read(tmp, 0, encryptedBytes.Length + 32);
                byte[] ret = new byte[len];
                Array.Copy(tmp, 0, ret, 0, len);
                return Encoding.UTF8.GetString(ret);
            }
            finally
            {
                cryptoStream.Close();
                mStream.Close();
                aes.Clear();
            }
        }
      /// <summary>
      /// AES有向量加密
      /// </summary>
      /// <param name="toEncrypt"></param>
      /// <param name="key"></param>
      /// <param name="iv"></param>
      /// <returns></returns>
        public static string AESEncrypt(string toEncrypt, string key, string iv)
        {
            try
            {
                byte[] keyArray = UTF8Encoding.UTF8.GetBytes(key);
                byte[] ivArray = UTF8Encoding.UTF8.GetBytes(iv);
                byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

                RijndaelManaged rDel = new RijndaelManaged();
                rDel.Key = keyArray;
                if (iv!="")
                rDel.IV = ivArray;
              //  rDel.KeySize = 128;
                rDel.Mode = CipherMode.CBC;
                rDel.Padding = PaddingMode.PKCS7;

                ICryptoTransform cTransform = rDel.CreateEncryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

                return Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }catch
            {
                return null;
            }
        }
       /// <summary>
       /// AES有向量解密
       /// </summary>
       /// <param name="toDecrypt"></param>
       /// <param name="key"></param>
       /// <param name="iv"></param>
       /// <returns></returns>
        public static string AESDecrypt(string toDecrypt, string key, string iv)
        {
            try
            {
                byte[] keyArray = UTF8Encoding.UTF8.GetBytes(key);
                byte[] ivArray = UTF8Encoding.UTF8.GetBytes(iv);
                byte[] toEncryptArray = Convert.FromBase64String(toDecrypt);

                RijndaelManaged rDel = new RijndaelManaged();
                rDel.Key = keyArray;
                rDel.IV = ivArray;
                rDel.Mode = CipherMode.CBC;
               // rDel.KeySize = 128;
                rDel.Padding = PaddingMode.PKCS7;

                ICryptoTransform cTransform = rDel.CreateDecryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                return UTF8Encoding.UTF8.GetString(resultArray);
            }
            catch
            {
                return null;
            }
        }
        /// <summary>
        /// 从适用于URL的Base64编码字符串转换为普通Base64字符串
        /// </summary>
        public static string Base64UrlToBase64(string str)
        {
            string temp = str.Replace('-', '+').Replace('_', '/');
            if (temp.Length % 4 != 0)
                temp = temp.PadRight(4 - (temp.Length % 4) + temp.Length, '=');//Base64字符串长度必须是4的倍数，不足的补成"="
            return temp;
        }
        /// <summary>
        /// 从普通Base64字符串转换为适用于URL的Base64编码字符串
        /// </summary>
        public static string Base64ToBase64Url(string str)
        {
            string temp = str.Replace('+', '-').Replace('/', '_').Replace("=", "");
            return temp;
        }
    }
}

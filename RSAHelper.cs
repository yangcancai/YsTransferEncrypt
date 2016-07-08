using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace YsTransferEncrypt
{
    public class RSAHelper
    {
        #region RSA 加密解密

        #region RSA 的密钥产生
        /// <summary>
        /// RSA产生密钥
        /// </summary>
        /// <param name="xmlKeys">私钥</param>
        /// <param name="xmlPublicKey">公钥</param>
        public static void GetRSAKey(out string xmlKeys, out string xmlPublicKey)
        {
            try
            {
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                xmlKeys = rsa.ToXmlString(true);
                xmlPublicKey = rsa.ToXmlString(false);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region RSA加密函数
        //############################################################################## 
        //RSA 方式加密 
        //KEY必须是XML的形式,返回的是字符串 
        //该加密方式有长度限制的！
        //############################################################################## 

        /// <summary>
        /// RSA的加密函数
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="encryptString">待加密的字符串</param>
        /// <returns></returns>
        public static string RSAEncrypt(string xmlPublicKey, string encryptString)
        {
            try
            {
                byte[] PlainTextBArray;
                byte[] CypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPublicKey);
                PlainTextBArray = Encoding.UTF8.GetBytes(encryptString);
                CypherTextBArray = rsa.Encrypt(PlainTextBArray, false);
                Result = Convert.ToBase64String(CypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA的加密函数 
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="EncryptString">待加密的字节数组</param>
        /// <returns></returns>
        public static string RSAEncrypt(string xmlPublicKey, byte[] EncryptString)
        {
            try
            {
                byte[] CypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPublicKey);
                CypherTextBArray = rsa.Encrypt(EncryptString, false);
                Result = Convert.ToBase64String(CypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region RSA的解密函数
        /// <summary>
        /// RSA的解密函数
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="decryptString">待解密的字符串</param>
        /// <returns></returns>
        public static string RSADecryptXmlKey(string xmlPrivateKey, string decryptString)
        {
            try
            {
                byte[] PlainTextBArray;
                byte[] DypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPrivateKey);
                PlainTextBArray = Convert.FromBase64String(decryptString);
                DypherTextBArray = rsa.Decrypt(PlainTextBArray, false);
                Result = (new UnicodeEncoding()).GetString(DypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA的解密函数
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="decryptString">待解密的字符串</param>
        /// <returns></returns>
        public static string RSADecrypt(string strPrivateKey, string decryptString)
        {
            try
            {
                byte[] PlainTextBArray;
                byte[] DypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(strPrivateKey);
                PlainTextBArray = Convert.FromBase64String(decryptString);
                DypherTextBArray = rsa.Decrypt(PlainTextBArray, false);
                Result = Encoding.UTF8.GetString(DypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA的解密函数 
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="DecryptString">待解密的字节数组</param>
        /// <returns></returns>
        public static string RSADecrypt(string xmlPrivateKey, byte[] DecryptString)
        {
            try
            {
                byte[] DypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPrivateKey);
                DypherTextBArray = rsa.Decrypt(DecryptString, false);
                Result = Encoding.UTF8.GetString(DypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #endregion

        #region RSA数字签名

        #region 获取Hash描述表
        /// <summary>
        /// 获取Hash描述表
        /// </summary>
        /// <param name="strSource">待签名的字符串</param>
        /// <param name="HashData">Hash描述</param>
        /// <returns></returns>
        public bool GetHash(string strSource, ref byte[] HashData)
        {
            try
            {
                byte[] Buffer;
                System.Security.Cryptography.HashAlgorithm MD5 = System.Security.Cryptography.HashAlgorithm.Create("MD5");
                Buffer = System.Text.Encoding.GetEncoding("GB2312").GetBytes(strSource);
                HashData = MD5.ComputeHash(Buffer);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 获取Hash描述表
        /// </summary>
        /// <param name="strSource">待签名的字符串</param>
        /// <param name="strHashData">Hash描述</param>
        /// <returns></returns>
        public bool GetHash(string strSource, ref string strHashData)
        {
            try
            {
                //从字符串中取得Hash描述 
                byte[] Buffer;
                byte[] HashData;
                System.Security.Cryptography.HashAlgorithm MD5 = System.Security.Cryptography.HashAlgorithm.Create("MD5");
                Buffer = System.Text.Encoding.GetEncoding("GB2312").GetBytes(strSource);
                HashData = MD5.ComputeHash(Buffer);
                strHashData = Convert.ToBase64String(HashData);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 获取Hash描述表
        /// </summary>
        /// <param name="objFile">待签名的文件</param>
        /// <param name="HashData">Hash描述</param>
        /// <returns></returns>
        public bool GetHash(System.IO.FileStream objFile, ref byte[] HashData)
        {
            try
            {
                //从文件中取得Hash描述 
                System.Security.Cryptography.HashAlgorithm MD5 = System.Security.Cryptography.HashAlgorithm.Create("MD5");
                HashData = MD5.ComputeHash(objFile);
                objFile.Close();
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 获取Hash描述表
        /// </summary>
        /// <param name="objFile">待签名的文件</param>
        /// <param name="strHashData">Hash描述</param>
        /// <returns></returns>
        public bool GetHash(System.IO.FileStream objFile, ref string strHashData)
        {
            try
            {
                //从文件中取得Hash描述 
                byte[] HashData;
                System.Security.Cryptography.HashAlgorithm MD5 = System.Security.Cryptography.HashAlgorithm.Create("MD5");
                HashData = MD5.ComputeHash(objFile);
                objFile.Close();
                strHashData = Convert.ToBase64String(HashData);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region RSA签名
        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="strKeyPrivate">私钥</param>
        /// <param name="HashbyteSignature">待签名Hash描述</param>
        /// <param name="EncryptedSignatureData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureFormatter(string strKeyPrivate, byte[] HashbyteSignature, ref byte[] EncryptedSignatureData)
        {
            try
            {
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();

                RSA.FromXmlString(strKeyPrivate);
                System.Security.Cryptography.RSAPKCS1SignatureFormatter RSAFormatter = new System.Security.Cryptography.RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5 
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名 
                EncryptedSignatureData = RSAFormatter.CreateSignature(HashbyteSignature);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="strKeyPrivate">私钥</param>
        /// <param name="HashbyteSignature">待签名Hash描述</param>
        /// <param name="m_strEncryptedSignatureData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureFormatter(string strKeyPrivate, byte[] HashbyteSignature, ref string strEncryptedSignatureData)
        {
            try
            {
                byte[] EncryptedSignatureData;
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPrivate);
                System.Security.Cryptography.RSAPKCS1SignatureFormatter RSAFormatter = new System.Security.Cryptography.RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5 
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名 
                EncryptedSignatureData = RSAFormatter.CreateSignature(HashbyteSignature);
                strEncryptedSignatureData = Convert.ToBase64String(EncryptedSignatureData);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="strKeyPrivate">私钥</param>
        /// <param name="strHashbyteSignature">待签名Hash描述</param>
        /// <param name="EncryptedSignatureData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureFormatter(string strKeyPrivate, string strHashbyteSignature, ref byte[] EncryptedSignatureData)
        {
            try
            {
                byte[] HashbyteSignature;

                HashbyteSignature = Convert.FromBase64String(strHashbyteSignature);
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();

                RSA.FromXmlString(strKeyPrivate);
                System.Security.Cryptography.RSAPKCS1SignatureFormatter RSAFormatter = new System.Security.Cryptography.RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5 
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名 
                EncryptedSignatureData = RSAFormatter.CreateSignature(HashbyteSignature);

                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="strKeyPrivate">私钥</param>
        /// <param name="strHashbyteSignature">待签名Hash描述</param>
        /// <param name="strEncryptedSignatureData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureFormatter(string strKeyPrivate, string strHashbyteSignature, ref string strEncryptedSignatureData)
        {
            try
            {
                byte[] HashbyteSignature;
                byte[] EncryptedSignatureData;
                HashbyteSignature = Convert.FromBase64String(strHashbyteSignature);
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPrivate);
                System.Security.Cryptography.RSAPKCS1SignatureFormatter RSAFormatter = new System.Security.Cryptography.RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5 
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名 
                EncryptedSignatureData = RSAFormatter.CreateSignature(HashbyteSignature);
                strEncryptedSignatureData = Convert.ToBase64String(EncryptedSignatureData);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region RSA 签名验证
        /// <summary>
        /// RSA签名验证
        /// </summary>
        /// <param name="strKeyPublic">公钥</param>
        /// <param name="HashbyteDeformatter">Hash描述</param>
        /// <param name="DeformatterData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string strKeyPublic, byte[] HashbyteDeformatter, byte[] DeformatterData)
        {
            try
            {
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPublic);
                System.Security.Cryptography.RSAPKCS1SignatureDeformatter RSADeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(RSA);
                //指定解密的时候HASH算法为MD5 
                RSADeformatter.SetHashAlgorithm("MD5");
                if (RSADeformatter.VerifySignature(HashbyteDeformatter, DeformatterData))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA签名验证
        /// </summary>
        /// <param name="strKeyPublic">公钥</param>
        /// <param name="strHashbyteDeformatter">Hash描述</param>
        /// <param name="DeformatterData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string strKeyPublic, string strHashbyteDeformatter, byte[] DeformatterData)
        {
            try
            {
                byte[] HashbyteDeformatter;
                HashbyteDeformatter = Convert.FromBase64String(strHashbyteDeformatter);
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPublic);
                System.Security.Cryptography.RSAPKCS1SignatureDeformatter RSADeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(RSA);
                //指定解密的时候HASH算法为MD5 
                RSADeformatter.SetHashAlgorithm("MD5");
                if (RSADeformatter.VerifySignature(HashbyteDeformatter, DeformatterData))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA签名验证
        /// </summary>
        /// <param name="strKeyPublic">公钥</param>
        /// <param name="HashbyteDeformatter">Hash描述</param>
        /// <param name="strDeformatterData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string strKeyPublic, byte[] HashbyteDeformatter, string strDeformatterData)
        {
            try
            {
                byte[] DeformatterData;
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPublic);
                System.Security.Cryptography.RSAPKCS1SignatureDeformatter RSADeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(RSA);
                //指定解密的时候HASH算法为MD5 
                RSADeformatter.SetHashAlgorithm("MD5");
                DeformatterData = Convert.FromBase64String(strDeformatterData);
                if (RSADeformatter.VerifySignature(HashbyteDeformatter, DeformatterData))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA签名验证
        /// </summary>
        /// <param name="strKeyPublic">公钥</param>
        /// <param name="strHashbyteDeformatter">Hash描述</param>
        /// <param name="strDeformatterData">签名后的结果</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string strKeyPublic, string strHashbyteDeformatter, string strDeformatterData)
        {
            try
            {
                byte[] DeformatterData;
                byte[] HashbyteDeformatter;
                HashbyteDeformatter = Convert.FromBase64String(strHashbyteDeformatter);
                System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();
                RSA.FromXmlString(strKeyPublic);
                System.Security.Cryptography.RSAPKCS1SignatureDeformatter RSADeformatter = new System.Security.Cryptography.RSAPKCS1SignatureDeformatter(RSA);
                //指定解密的时候HASH算法为MD5 
                RSADeformatter.SetHashAlgorithm("MD5");
                DeformatterData = Convert.FromBase64String(strDeformatterData);
                if (RSADeformatter.VerifySignature(HashbyteDeformatter, DeformatterData))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #endregion

        #region 非对称RSA 私钥加密公钥解密
        /// <summary>
        /// 非对称RSA加密类 可以参考
        /// http://www.cnblogs.com/hhh/archive/2011/06/03/2070692.html
        /// http://blog.csdn.net/zhilunchen/article/details/2943158
        /// 若是私匙加密 则需公钥解密
        /// 反正公钥加密 私匙来解密
        /// 需要BigInteger类来辅助
        /// </summary>
            /// <summary>
            /// RSA的容器 可以解密的源字符串长度为 DWKEYSIZE/8-11 
            /// </summary>
            public const int DWKEYSIZE = 1024;

            /// <summary>
            /// RSA加密的密匙结构  公钥和私匙
            /// </summary>
            public struct RSAKey
            {
                public string PublicKey { get; set; }
                public string PrivateKey { get; set; }
            }

            #region 得到RSA的解谜的密匙对
            /// <summary>
            /// 得到RSA的解谜的密匙对
            /// </summary>
            /// <returns></returns>
            public static RSAKey GetRASKey()
            {
                RSACryptoServiceProvider.UseMachineKeyStore = true;
                //声明一个指定大小的RSA容器
                RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(DWKEYSIZE);
                //取得RSA容易里的各种参数
                RSAParameters p = rsaProvider.ExportParameters(true);

                return new RSAKey()
                {
                    PublicKey = ComponentKey(p.Exponent, p.Modulus),
                    PrivateKey = ComponentKey(p.D, p.Modulus)
                };
            }
            #endregion

            #region 检查明文的有效性 DWKEYSIZE/8-11 长度之内为有效 中英文都算一个字符
            /// <summary>
            /// 检查明文的有效性 DWKEYSIZE/8-11 长度之内为有效 中英文都算一个字符
            /// </summary>
            /// <param name="source"></param>
            /// <returns></returns>
            public static bool CheckSourceValidate(string source)
            {
                return (DWKEYSIZE / 8 - 11) >= source.Length;
            }
            #endregion

            #region 组合解析密匙
            /// <summary>
            /// 组合成密匙字符串
            /// </summary>
            /// <param name="b1"></param>
            /// <param name="b2"></param>
            /// <returns></returns>
            private static string ComponentKey(byte[] b1, byte[] b2)
            {
                List<byte> list = new List<byte>();
                //在前端加上第一个数组的长度值 这样今后可以根据这个值分别取出来两个数组
                list.Add((byte)b1.Length);
                list.AddRange(b1);
                list.AddRange(b2);
                byte[] b = list.ToArray<byte>();
                return Convert.ToBase64String(b);
            }

            /// <summary>
            /// 解析密匙
            /// </summary>
            /// <param name="key">密匙</param>
            /// <param name="b1">RSA的相应参数1</param>
            /// <param name="b2">RSA的相应参数2</param>
            private static void ResolveKey(string key, out byte[] b1, out byte[] b2)
            {
                //从base64字符串 解析成原来的字节数组
                byte[] b = Convert.FromBase64String(key);
                //初始化参数的数组长度
                b1 = new byte[b[0]];
                b2 = new byte[b.Length - b[0] - 1];
                //将相应位置是值放进相应的数组
                for (int n = 1, i = 0, j = 0; n < b.Length; n++)
                {
                    if (n <= b[0])
                    {
                        b1[i++] = b[n];
                    }
                    else
                    {
                        b2[j++] = b[n];
                    }
                }
            }
            #endregion

            #region 字符串加密解密 公开方法
            /// <summary>
            /// 字符串加密
            /// </summary>
            /// <param name="source">源字符串 明文</param>
            /// <param name="key">密匙</param>
            /// <returns>加密遇到错误将会返回原字符串</returns>
            public static string EncryptString(string source, string key)
            {
                string encryptString = string.Empty;
                byte[] d;
                byte[] n;
                try
                {
                    if (!CheckSourceValidate(source))
                    {
                        throw new Exception("source string too long");
                    }
                    //解析这个密钥
                    ResolveKey(key, out d, out n);
                    BigInteger biN = new BigInteger(n);
                    BigInteger biD = new BigInteger(d);
                    encryptString = EncryptString(source, biD, biN);
                }
                catch
                {
                    encryptString = source;
                }
                return encryptString;
            }

            /// <summary>
            /// 字符串解密
            /// </summary>
            /// <param name="encryptString">密文</param>
            /// <param name="key">密钥</param>
            /// <returns>遇到解密失败将会返回原字符串</returns>
            public static string DecryptString(string encryptString, string key)
            {
                string source = string.Empty;
                byte[] e;
                byte[] n;
                try
                {
                    //解析这个密钥
                    ResolveKey(key, out e, out n);
                    BigInteger biE = new BigInteger(e);
                    BigInteger biN = new BigInteger(n);
                    source = DecryptString(encryptString, biE, biN);
                }
                catch
                {
                    source = encryptString;
                }
                return source;
            }
            #endregion

            #region 字符串加密解密 私有  实现加解密的实现方法
            /// <summary>
            /// 用指定的密匙加密 
            /// </summary>
            /// <param name="source">明文</param>
            /// <param name="d">可以是RSACryptoServiceProvider生成的D</param>
            /// <param name="n">可以是RSACryptoServiceProvider生成的Modulus</param>
            /// <returns>返回密文</returns>
            private static string EncryptString(string source, BigInteger d, BigInteger n)
            {
                int len = source.Length;
                int len1 = 0;
                int blockLen = 0;
                if ((len % 128) == 0)
                    len1 = len / 128;
                else
                    len1 = len / 128 + 1;
                string block = "";
                StringBuilder result = new StringBuilder();
                for (int i = 0; i < len1; i++)
                {
                    if (len >= 128)
                        blockLen = 128;
                    else
                        blockLen = len;
                    block = source.Substring(i * 128, blockLen);
                    byte[] oText = System.Text.Encoding.Default.GetBytes(block);
                    BigInteger biText = new BigInteger(oText);
                    BigInteger biEnText = biText.modPow(d, n);
                    string temp = biEnText.ToHexString();
                    result.Append(temp).Append("@");
                    len -= blockLen;
                }
                return result.ToString().TrimEnd('@');
            }

            /// <summary>
            /// 用指定的密匙加密 
            /// </summary>
            /// <param name="source">密文</param>
            /// <param name="e">可以是RSACryptoServiceProvider生成的Exponent</param>
            /// <param name="n">可以是RSACryptoServiceProvider生成的Modulus</param>
            /// <returns>返回明文</returns>
            private static string DecryptString(string encryptString, BigInteger e, BigInteger n)
            {
                StringBuilder result = new StringBuilder();
                string[] strarr1 = encryptString.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < strarr1.Length; i++)
                {
                    string block = strarr1[i];
                    BigInteger biText = new BigInteger(block, 16);
                    BigInteger biEnText = biText.modPow(e, n);
                    string temp = System.Text.Encoding.Default.GetString(biEnText.getBytes());
                    result.Append(temp);
                }
                return result.ToString();
            }
            #endregion
        #endregion

    }
}

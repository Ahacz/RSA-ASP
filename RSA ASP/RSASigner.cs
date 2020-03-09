using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace RSA_ASP
{
    public class RSASigner
    {
        public static AsymmetricCipherKeyPair GetKeyPairWithDotNet()
        {
            using (RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider())
            {
                RsaKeyPairGenerator r = new RsaKeyPairGenerator();
                r.Init(new KeyGenerationParameters(new SecureRandom(),
                      1024));
                AsymmetricCipherKeyPair keys = r.GenerateKeyPair();
                return keys;
            }
        }
        public static string FormatToPEM(AsymmetricKeyParameter item)
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(item);
            pemWriter.Writer.Flush();
            return textWriter.ToString();
        }
        public static AsymmetricCipherKeyPair ReadFromPem(string pemEncodedKey)
        {
            AsymmetricCipherKeyPair result = null;
            using (var stringReader = new StringReader(pemEncodedKey))
            {
                var pemReader = new PemReader(stringReader);
                var pemObject = pemReader.ReadObject(); // null!
                result = (AsymmetricCipherKeyPair)pemObject;
            }

            return result;
        }

        public static String Sign(byte[] data, string [] RSAPriv)
        {

            string input = string.Join("\n", RSAPriv);
            AsymmetricCipherKeyPair givenKey = ReadFromPem(input);
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
            var rsaParameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)givenKey.Private);
            RSAalg.ImportParameters(rsaParameters);
            var sha = new SHA1CryptoServiceProvider();
            byte[] hash = sha.ComputeHash(data);
            var sig = RSAalg.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            return Convert.ToBase64String(sig);
        }

        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RsaKeyParameters key)
        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                var rsaParameters = DotNetUtilities.ToRSAParameters(key);
                RSAalg.ImportParameters(rsaParameters);
                return RSAalg.VerifyData(DataToVerify, new SHA1CryptoServiceProvider(), SignedData);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }
    }
}
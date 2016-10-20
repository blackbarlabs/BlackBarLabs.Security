﻿using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace BlackBarLabs.Security.Crypto
{
    public static class CryptoTools
    {
        public static string Base64Encode(string text)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string value)
        {
            var base64EncodedBytes = Convert.FromBase64String(value);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public static string UrlBase64Encode(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            return System.Web.HttpServerUtility.UrlTokenEncode(bytes);
        }

        public static string UrlBase64Decode(string text)
        {
            var bytes = System.Web.HttpServerUtility.UrlTokenDecode(text);
            return Encoding.UTF8.GetString(bytes);
        }

        public static SecurityToken GetRsaSecurityToken(string base64EncodedValue)
        {
            var xml = UrlBase64Decode(base64EncodedValue);
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xml);
            return new RsaSecurityToken(rsa);
        }

        public delegate T GenerateHashDelegate<T>(string salt, string hash);

        public static T GenerateHash<T>(string password, GenerateHashDelegate<T> callback)
        {
            var saltBytes = PasswordToolkit.GetRandomSalt();
            var hash = PasswordToolkit.PasswordToHashHexString(saltBytes, PasswordToolkit.PasswordToHashHexString(saltBytes, password));
            var salt = PasswordToolkit.HashBytesToHexString(saltBytes);

            return callback(salt, hash);
        }

        public static T GenerateHash<T>(string password, string salt, GenerateHashDelegate<T> callback)
        {
            var saltBytes = PasswordToolkit.HashHexStringToBytes(salt);
            var hash = PasswordToolkit.PasswordToHashHexString(saltBytes, PasswordToolkit.PasswordToHashHexString(saltBytes, password));

            return callback(salt, hash);
        }

        public static bool TestPassword(string password, string hash, string salt)
        {
            if (string.IsNullOrWhiteSpace(hash) || string.IsNullOrWhiteSpace(salt))
            {
                return false;
            }
            return Compare(password, hash, salt);
        }

        private static bool Compare(string password, string hash, string salt)
        {
            return GenerateHash(password, salt, (generatedSalt, generatedHash) => 
                hash.Equals(generatedHash, StringComparison.OrdinalIgnoreCase));
        }
    }
}

﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.Crypto
{
    public class Rsa
    {

        public static byte[] ComputeHashData(string data, out byte[] signatureData)
        {
            signatureData = Encoding.ASCII.GetBytes(data);
            var hash = new SHA256Managed();
            var hashedData = hash.ComputeHash(signatureData);
            return hashedData;
        }


        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSACryptoServiceProvider rsaProvider)
        {
            try
            {
                byte[] encryptedData;

                //Encrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                encryptedData = rsaProvider.Encrypt(DataToEncrypt, false);

                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSACryptoServiceProvider rsaProvider)
        {
            try
            {
                byte[] decryptedData;
                //Decrypt the passed byte array and specify OAEP padding.  
                //OAEP padding is only available on Microsoft Windows XP or
                //later.  
                decryptedData = rsaProvider.Decrypt(DataToDecrypt, false);

                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }
    }
}
﻿using BlackBarLabs.Security.Crypto;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.WindowsAzure;

namespace BlackBarLabs.Security
{
    public static class RSA
    {
        public static TResult FromConfig<TResult>(string secretAsRSAXmlBase64,
            Func<RSACryptoServiceProvider, TResult> success,
            Func<string, TResult> invalidSecret)
        {
            try
            {
                var bytes = Convert.FromBase64String(secretAsRSAXmlBase64);
                var xml = Encoding.ASCII.GetString(bytes);
                var rsaProvider = new RSACryptoServiceProvider();
                try
                {
                    rsaProvider.FromXmlString(xml);
                    return success(rsaProvider);
                }
                catch (CryptographicException ex)
                {
                    return invalidSecret(ex.Message);
                }
            } catch(FormatException ex)
            {
                return invalidSecret(ex.Message);
            }
        }

        public static TResult FromConfig<TResult>(string configSettingName,
            Func<RSACryptoServiceProvider, TResult> success,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting)
        {
            var secretAsRSAXmlBase64 = Microsoft.Azure.CloudConfigurationManager.GetSetting(configSettingName);
            if (string.IsNullOrWhiteSpace(secretAsRSAXmlBase64))
                return missingConfigurationSetting(configSettingName);

            try
            {
                var bytes = Convert.FromBase64String(secretAsRSAXmlBase64);
                var xml = Encoding.ASCII.GetString(bytes);
                var rsaProvider = new RSACryptoServiceProvider();
                try
                {
                    rsaProvider.FromXmlString(xml);
                    return success(rsaProvider);
                }
                catch (CryptographicException ex)
                {
                    return invalidConfigurationSetting(configSettingName, ex.Message);
                }
            }
            catch (FormatException ex)
            {
                return invalidConfigurationSetting(configSettingName, ex.Message);
            }
        }

        public static TResult Generate<TResult>(Func<string, string, TResult> success)
        {
            var cspParams = new CspParameters()
            {
                ProviderType = 1, // PROV_RSA_FULL
                Flags = CspProviderFlags.UseArchivableKey,
                KeyNumber = (int)KeyNumber.Exchange,
            };
            var rsaProvider = new RSACryptoServiceProvider(2048, cspParams);

            // Export public key
            var publicKey = Convert.ToBase64String(
                Encoding.ASCII.GetBytes(
                    rsaProvider.ToXmlString(false)));
            
            // Export private/public key pair
            var privateKey = Convert.ToBase64String(
                Encoding.ASCII.GetBytes(
                    rsaProvider.ToXmlString(true)));

            return success(publicKey, privateKey);
        }
    }
}

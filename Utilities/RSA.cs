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
        public static RSACryptoServiceProvider RSAFromConfig(string configSettingName)
        {
            var secretAsRSAXmlBase64 =  CloudConfigurationManager.GetSetting(configSettingName);
            if (string.IsNullOrEmpty(secretAsRSAXmlBase64))
                throw new SystemException("RSA public key was not found in the configuration file. AppSetting = " + configSettingName);
            var xml = CryptoTools.UrlBase64Decode(secretAsRSAXmlBase64);
            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(xml);
            return rsaProvider;
        }
    }
}

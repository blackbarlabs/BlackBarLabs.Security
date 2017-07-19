using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EastFive.Security
{
    public static class AppSettings
    {
        // Key Signature
        public const string TokenScope = "EastFive.Security.Token.Scope";
        public const string TokenIssuer = "EastFive.Security.Token.Issuer";
        public const string TokenKey = "EastFive.Security.Token.Key";

        public const string CredentialProviderVoucherKey = "EastFive.Security.CredentialProvider.Voucher.Key";
        public const string CredentialProviderVoucherProviderId = "EastFive.Security.CredentialProvider.Voucher.Provider";

        /// <summary>
        /// The certificate the SAML provider offers. It is in base64 format. Only the public key is availble. It is used
        /// to verfiy the signature of the SAML assurtion.
        /// </summary>
        public const string SAMLCertificate = "EastFive.Security.CredentialProvider.SAML.Certificate";
        /// <summary>
        /// The name of the attribute in the SAML assurtion whos value contains the key that is used to lookup the
        /// user in the local system.
        /// </summary>
        public const string SAMLLoginIdAttributeName = "EastFive.Security.CredentialProvider.SAML.LoginIdAttributeName";
    }
}

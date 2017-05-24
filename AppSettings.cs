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
    }
}

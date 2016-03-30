using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using BlackBarLabs.Security.Crypto;
using Microsoft.Owin.Security;

namespace BlackBarLabs.Security.Tokens
{
    public static class JwtTools
    {
        public static bool ValidateClaim(this IEnumerable<Claim> claims,
            string claimId, string expectedValue, Action<string> onFail)
        {
            var claim = claims.FirstOrDefault(x => x.Type == claimId);
            if (default(Claim) == claim)
            {
                onFail(default(string));
                return false;
            }
            if(String.Compare(claim.Value, expectedValue) != 0)
            {
                onFail(claim.Value);
                return false;
            }
            return true;
        }

        public static bool ValidateClaim(this IEnumerable<Claim> claims,
            string claimId, Guid expectedValue, Action<string> onFail)
        {
            var claim = claims.FirstOrDefault(x => x.Type == claimId);
            if (default(Claim) == claim)
            {
                onFail(default(string));
                return false;
            }

            Guid claimGuid;
            if (!Guid.TryParse(claim.Value, out claimGuid))
            {
                onFail(claim.Value);
                return false;
            }

            if (claimGuid != expectedValue)
            {
                onFail(claim.Value);
                return false;
            }

            return true;
        }

        public static bool ValidateAuthorizationClaim(this IEnumerable<Claim> claims,
            Guid expectedValue, Action<string> onFail)
        {
            return ValidateClaim(claims, ClaimIds.Authorization, expectedValue, onFail);
        }

        public static bool ValidateSessionClaim(this IEnumerable<Claim> claims,
            Guid expectedValue, Action<string> onFail)
        {
            return ValidateClaim(claims, ClaimIds.Session, expectedValue, onFail);
        }

        public static bool TryParseJwtSecurityToken(
            this string jwtEncodedString,
            string configNameOfRsaKeyToValidateAgainst,
            string configNameOfIssuerToValidateAgainst,
            out Claim [] claims)
        {
            var handler = new JwtSecurityTokenHandler();
            
            var rsaProvider = RSA.RSAFromConfig(configNameOfRsaKeyToValidateAgainst);
            var securityToken = new RsaSecurityToken(rsaProvider);
            
            var issuer = ConfigurationManager.AppSettings[configNameOfIssuerToValidateAgainst];
            if (string.IsNullOrEmpty(issuer)) throw new SystemException("Issuer was not found in the configuration file");

            var validationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidIssuer = issuer,
                IssuerSigningTokens = new RsaSecurityToken [] { securityToken },
                RequireExpirationTime = true,
            };

            try
            {
                SecurityToken validatedToken;
                var principal = handler.ValidateToken(jwtEncodedString, validationParameters, out validatedToken);
                claims = principal.Claims.ToArray();
                return true;
            }
            catch (ArgumentException)
            {
                claims = default(Claim[]);
                return false;
            }
        }

        public static string CreateToken(AuthenticationTicket data)
        {
            string clientId = data.Properties.Dictionary.ContainsKey("audience") ? data.Properties.Dictionary["audience"] : null;
            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;
            return CreateToken(clientId, issued, expires, data.Identity.Claims);
        }

        public static string CreateToken(Guid sessionId, Guid authorizationId, double tokenExpirationInMinutes,
             int role, string configNameOfIssuer = "BlackBarLabs.Security.issuer", string configNameOfRSAKey = "BlackBarLabs.Security.secret")
        {
            var claims = new[] {
                new Claim(ClaimIds.Session, sessionId.ToString()),
                new Claim(ClaimIds.Role, role.ToString()),
                new Claim(ClaimIds.Authorization, authorizationId.ToString()) };
            
            var issued = DateTime.UtcNow;
            var validForDuration = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(tokenExpirationInMinutes);
            var jwtToken = CreateToken(sessionId.ToString("N"),
                issued, validForDuration, claims,
                configNameOfIssuer, configNameOfRSAKey);
            return jwtToken;

        }

        public static string CreateToken(Guid sessionId, Guid authorizationId, double tokenExpirationInMinutes,
            string configNameOfIssuer = "BlackBarLabs.Security.issuer", string configNameOfRSAKey = "BlackBarLabs.Security.secret")
        {
            var claims = new[] {
                new Claim(ClaimIds.Session, sessionId.ToString()),
                new Claim(ClaimIds.Authorization, authorizationId.ToString()) };

            var issued = DateTime.UtcNow;
            var validForDuration = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(tokenExpirationInMinutes);
            var jwtToken = CreateToken(sessionId.ToString("N"),
                issued, validForDuration, claims,
                configNameOfIssuer, configNameOfRSAKey);
            return jwtToken;

        }

        public static string CreateToken(string clientId,
            DateTimeOffset? issued, DateTimeOffset? expires,
            IEnumerable<Claim> claims,
            string configNameOfIssuer = "BlackBarLabs.Security.issuer", string configNameOfRSAKey = "BlackBarLabs.Security.secret")
        {
            var rsaProvider = RSA.RSAFromConfig(configNameOfRSAKey);
            var securityKey = new RsaSecurityKey(rsaProvider);

            var issuer = ConfigurationManager.AppSettings[configNameOfIssuer];
            if (string.IsNullOrEmpty(issuer))
                throw new SystemException("Issuer was not found in the configuration file");
            
            var token = new JwtSecurityToken(issuer, clientId, claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime,
                new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature,
                    SecurityAlgorithms.Sha256Digest));

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);
            return jwt;
        }
    }
}

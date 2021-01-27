/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */


using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;
using static Providers.WxWorkIntegration.WxWorkAuthenticationConstants;

namespace Providers.WxWorkIntegration
{
    public class WxWorkAuthenticationOptions : OAuthOptions
    {
        /// <summary>
        /// Authorizer's web application ID
        /// </summary>
        public string Agentid { get; set; }
        public bool SilentAuthorizationEnable { get; set; }
        public bool ScanCodeAuthorizationEnable { get; set; }
        public string MemberInformationEndpoint { get; set; }
        public string UserIdConvertToOpenIdEndpoint { get; set; }

        public WxWorkAuthenticationOptions()
        {
            CallbackPath = WxWorkAuthenticationDefaults.CallbackPath;
            ClaimsIssuer = WxWorkAuthenticationDefaults.Issuer;

            AuthorizationEndpoint = WxWorkAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = WxWorkAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = WxWorkAuthenticationDefaults.UserInformationEndpoint;
            MemberInformationEndpoint = WxWorkAuthenticationDefaults.MemberInformationEndpoint;
            UserIdConvertToOpenIdEndpoint = WxWorkAuthenticationDefaults.UserIdConvertToOpenIdEndpoint;

            Scope.Add("snsapi_base");

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "openid");

            ClaimActions.MapJsonKey(JwtClaimTypes.Name, "name");
            ClaimActions.MapJsonKey(JwtClaimTypes.NickName, "alias");
            ClaimActions.MapJsonKey(JwtClaimTypes.Email, "email");
            ClaimActions.MapJsonKey(JwtClaimTypes.PhoneNumber, "mobile");
            ClaimActions.MapJsonKey(JwtClaimTypes.Address, "address");
            ClaimActions.MapJsonKey(JwtClaimTypes.Gender, "gender");
            ClaimActions.MapJsonKey(JwtClaimTypes.Subject, "openid");
            ClaimActions.MapJsonKey(JwtClaimTypes.Picture, "avatar");

            ClaimActions.MapJsonKey(Claims.Userid, "userid");
            ClaimActions.MapJsonKey(Claims.OpenUserId, "openid");
            ClaimActions.MapJsonKey(Claims.AccountStatus, "status");
        }
    }
}

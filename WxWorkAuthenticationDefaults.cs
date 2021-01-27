/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Providers.WxWorkIntegration
{
    public static class WxWorkAuthenticationDefaults
    {
        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = "WxWork";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.SilentAuthenticationScheme"/>.
        /// </summary>
        public const string SilentAuthenticationScheme = "WxWork-Silent";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.ScanCodeAuthenticationScheme"/>.
        /// </summary>
        public const string ScanCodeAuthenticationScheme = "WxWork-ScanCode";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "WxWork";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-wxwork";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "WxWork";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationDefaults.AuthorizationEndpoint"/>.
        /// </summary>
        public const string AuthorizationEndpoint = "";

        /// <summary>
        /// Default value for silent authorization endpoint on the WeChat webpage/>.
        /// </summary>
        public const string SilentAuthorizationEndpoint = "https://open.weixin.qq.com/connect/oauth2/authorize";

        /// <summary>
        /// Default value for scan code login endpoint/>.
        /// </summary>
        public const string ScanCodeAuthorizationEndpoint = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        public const string TokenEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.UserInformationEndpoint"/>.
        /// </summary>
        public const string UserInformationEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationOptions.MemberInformationEndpoint"/>.
        /// </summary>
        public const string MemberInformationEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/user/get";

        /// <summary>
        /// Default value for <see cref="WxWorkAuthenticationOptions.UserIdConvertToOpenIdEndpoint"/>.
        /// </summary>
        public const string UserIdConvertToOpenIdEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/user/convert_to_openid";
    }
}

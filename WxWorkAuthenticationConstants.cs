/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace Providers.WxWorkIntegration
{
    /// <summary>
    /// Contains constants specific to the <see cref="WxWorkAuthenticationHandler"/>.
    /// </summary>
    public static class WxWorkAuthenticationConstants
    {
        public static class Claims
        {
            public const string Userid = "urn:wxwork:userid";
            public const string OpenUserId = "urn:wxwork:open_userid";
            public const string AccountStatus = "urn:wxwork:account_status";
        }
    }
}

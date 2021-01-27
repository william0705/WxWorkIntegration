/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */


using Providers.WxWorkIntegration;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WxWorkAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="WxWorkAuthenticationDefaults"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables WxWork authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthenticationBuilder AddWxWorkAuthentication(this AuthenticationBuilder builder)
        {
            return builder.AddWxWorkAuthentication(WxWorkAuthenticationDefaults.AuthenticationScheme, options => { });
        }

        /// <summary>
        /// Adds <see cref="WxWorkAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables WxWork authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthenticationBuilder AddWxWorkAuthentication(
            this AuthenticationBuilder builder,
            Action<WxWorkAuthenticationOptions> configuration)
        {
            return builder.AddWxWorkAuthentication(WxWorkAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds <see cref="WxWorkAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables WxWork authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the WxWork options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddWxWorkAuthentication(
             this AuthenticationBuilder builder,
             string scheme,
             Action<WxWorkAuthenticationOptions> configuration)
        {
            return builder.AddWxWorkAuthentication(scheme, WxWorkAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="WxWorkAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables WxWork authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the WxWork options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddWxWorkAuthentication(
            this AuthenticationBuilder builder,
            string scheme,
            string caption,
            Action<WxWorkAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<WxWorkAuthenticationOptions, WxWorkAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}

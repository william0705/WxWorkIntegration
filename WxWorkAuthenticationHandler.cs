/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

namespace Providers.WxWorkIntegration
{
    public class WxWorkAuthenticationHandler : OAuthHandler<WxWorkAuthenticationOptions>
    {
        public WxWorkAuthenticationHandler(
            [NotNull] IOptionsMonitor<WxWorkAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override string BuildChallengeUrl([NotNull] AuthenticationProperties properties,
            [NotNull] string redirectUri)
        {
            if (StringValues.IsNullOrEmpty(Options.AuthorizationEndpoint))
            {
                throw new ArgumentNullException(nameof(Options.AuthorizationEndpoint), "Please check the setting of AuthorizationEndpoint.");
            }

            var stateValue = Options.StateDataFormat.Protect(properties);

            if (Options.ScanCodeAuthorizationEnable)
            {
                if (StringValues.IsNullOrEmpty(Options.Agentid))
                {
                    throw new ArgumentNullException(nameof(Options.Agentid), "AgentId is necessary.");
                }
                ////Construct enterprise WeChat scan code login link
                return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
                {
                    ["appid"] = Options.ClientId,
                    ["agentid"] = Options.Agentid,
                    ["state"] = stateValue,
                    ["redirect_uri"] = redirectUri
                });
            }
            else if (Options.SilentAuthorizationEnable)
            {
                //Construct silent authorization link on the corporate WeChat webpage
                return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
                {
                    ["appid"] = Options.ClientId,
                    ["redirect_uri"] = redirectUri,
                    ["response_type"] = "code",
                    ["scope"] = FormatScope(),
                    ["state"] = stateValue + "#wechat_redirect"
                });
            }
            throw new BuildChallengeException("Need to add other ways to build challenge url.");
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;
            var code = query["code"];
            var state = query["state"].ToString().Split("#wechat_redirect")[0];

            var properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            //if (!ValidateCorrelationId(properties))
            //{
            //    return HandleRequestResult.Fail("Correlation failed.");
            //}

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.");
            }

            var tokens = await ExchangeCodeAsync(new OAuthCodeExchangeContext(properties, code, properties.RedirectUri));
            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>
                {
                    new AuthenticationToken {Name = "access_token", Value = tokens.AccessToken}
                };
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }
                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                    {
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }
                properties.StoreTokens(authTokens);
            }

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            return ticket != null
                ? HandleRequestResult.Success(ticket)
                : HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(
            OAuthCodeExchangeContext context)
        {
            Dictionary<string, string> param = new Dictionary<string, string>
            {
                { "corpid", Options.ClientId },
                { "corpsecret", Options.ClientSecret }
            };

            var stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");

            var response = await Backchannel.PostAsync(Options.TokenEndpoint, stringContent);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }

            JObject payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            if (payload.Value<int>("errcode") != 0)
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }

            var jsonDocument = JsonDocument.Parse(payload.ToString());
            return OAuthTokenResponse.Success(jsonDocument);
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var query = Request.Query;
            var code = query["code"];

            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
                ["code"] = code
            });

            var response = await Backchannel.GetAsync(address);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            if (payload.Value<int>("errcode") != 0)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            var userId = payload.Value<string>("UserId");
            if (StringValues.IsNullOrEmpty(userId))
            {
                throw new HttpRequestException("Non-corporate members cannot obtain corporate member information.");
            }
            var getMemberInfoAddress = QueryHelpers.AddQueryString(Options.MemberInformationEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
                ["userid"] = userId
            });

            var memberInfoResponse = await Backchannel.GetAsync(getMemberInfoAddress);
            if (!memberInfoResponse.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                    /* Status: */ memberInfoResponse.StatusCode,
                    /* Headers: */ memberInfoResponse.Headers.ToString(),
                    /* Body: */ await memberInfoResponse.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving member information.");
            }

            var memberInfoPayload = JObject.Parse(await memberInfoResponse.Content.ReadAsStringAsync());
            if (memberInfoPayload.Value<int>("errcode") != 0)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                    /* Status: */ memberInfoResponse.StatusCode,
                    /* Headers: */ memberInfoResponse.Headers.ToString(),
                    /* Body: */ await memberInfoResponse.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving member information.");
            }

            var userIdConvertToOpenIdAddress = QueryHelpers.AddQueryString(
                WxWorkAuthenticationDefaults.UserIdConvertToOpenIdEndpoint, new Dictionary<string, string>()
                {
                    ["access_token"] = tokens.AccessToken
                });

            Dictionary<string, string> param = new Dictionary<string, string>
            {
                { "userid", userId }
            };

            var stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");

            var convertResponse = await Backchannel.PostAsync(userIdConvertToOpenIdAddress, stringContent);
            if (!convertResponse.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                    /* Status: */ convertResponse.StatusCode,
                    /* Headers: */ convertResponse.Headers.ToString(),
                    /* Body: */ await convertResponse.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while userid convert to openid.");
            }

            var convertResponsePayload = JObject.Parse(await convertResponse.Content.ReadAsStringAsync());

            if (convertResponsePayload.Value<int>("errcode") != 0)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                    /* Status: */ convertResponse.StatusCode,
                    /* Headers: */ convertResponse.Headers.ToString(),
                    /* Body: */ await convertResponse.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while userid convert to openid.");
            }

            var jObject = new JObject();
            jObject.TryAppend(memberInfoPayload).TryAppend(convertResponsePayload);

            var resultPayload = JsonDocument.Parse(jObject.ToString());
            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, resultPayload.RootElement);
            context.RunClaimActions(resultPayload.RootElement);

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        protected override string FormatScope() => string.Join(",", Options.Scope);
    }

    public class BuildChallengeException : Exception
    {
        public BuildChallengeException()
        {
        }

        public BuildChallengeException(string message) : base(message)
        {
        }

        public BuildChallengeException(string message, Exception inner) : base(message, inner)
        {
        }

        protected BuildChallengeException(
            SerializationInfo info,
            StreamingContext context) : base(info, context)
        {
        }
    }
}

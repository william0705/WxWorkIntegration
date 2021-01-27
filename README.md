# WxWorkIntegration
企业微信Identity 静默授权/扫码登陆

使用说明：


var wxWorkConfiguration = configuration.GetSection(ConfigurationConsts.WxWorkProviderKey)
                .Get<WxWorkConfiguration>();
            if (wxWorkConfiguration.SilentAuthorizationEnable)
            {
                authenticationBuilder.AddWxWorkAuthentication(
                    WxWorkAuthenticationDefaults.SilentAuthenticationScheme, "企业微信静默授权",
                    options =>
                    {
                        options.ClientId = wxWorkConfiguration.ClientId;
                        options.ClientSecret = wxWorkConfiguration.ClientSecret;
                        options.AuthorizationEndpoint = WxWorkAuthenticationDefaults.SilentAuthorizationEndpoint;
                        options.SaveTokens = true;
                        options.SilentAuthorizationEnable = true;
                        options.CallbackPath=new PathString("/signin-wxwork-silentLogin");

                        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
                        options.ClaimActions.MapJsonKey(ClaimTypes.MobilePhone, "mobile");
                    });
            }

            if (wxWorkConfiguration.ScanCodeAuthorizationEnable)
            {
                authenticationBuilder.AddWxWorkAuthentication(WxWorkAuthenticationDefaults.ScanCodeAuthenticationScheme, "企业微信扫码登录",
                    options =>
                    {
                        options.ClientId = wxWorkConfiguration.ClientId;
                        options.Agentid = wxWorkConfiguration.AgentId;
                        options.ClientSecret = wxWorkConfiguration.ClientSecret;
                        options.AuthorizationEndpoint = WxWorkAuthenticationDefaults.ScanCodeAuthorizationEndpoint;
                        options.SaveTokens = true;
                        options.ScanCodeAuthorizationEnable = true;
                        options.CallbackPath = new PathString("/signin-wxwork-scanCodeLogin");

                        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
                        options.ClaimActions.MapJsonKey(ClaimTypes.MobilePhone, "mobile");
                    });
            }

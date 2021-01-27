/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */


using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace Providers.WxWorkIntegration
{
    public static class JObjectExtensions
    {
        public static JObject TryAppend(this JObject jObject, JObject appendJObject)
        {
            foreach (var (key, value) in appendJObject)
            {
                jObject.TryAdd(key, value);
            }

            return jObject;
        }
    }
}

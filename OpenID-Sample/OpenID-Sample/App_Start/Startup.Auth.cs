using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using OpenID_Sample.Models;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Net.Http;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace OpenID_Sample
{
    public partial class Startup {

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301883
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = "ClientCookie",
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "ClientCookie",
                ExpireTimeSpan = TimeSpan.FromMinutes(5)
            });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                    SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),
                    ClientId = "a79acc19c5ddd565007918d7e3a61cd490de86e5ec9179f445802285b4750999",
                    ClientSecret = "214e85448c1f3c276797ab49e3817804c9555a39b4cc025fa00a135206d8b19d",
                    Authority = "https://oauth2id.dev/",
                    RequireHttpsMetadata = true,
                    ResponseType = "code",
                    Scope = "openid",
                    RedirectUri = "https://localhost:44352/",

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthorizationCodeReceived = async (notification) =>
                        {
                            using (var client = new HttpClient())
                            {
                                var configuration = await notification.Options.ConfigurationManager.GetConfigurationAsync(notification.Request.CallCancelled);
                                var request = new HttpRequestMessage(HttpMethod.Get, configuration.TokenEndpoint);
                                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                               {
                                    {OpenIdConnectParameterNames.ClientId, notification.Options.ClientId},
                                    {OpenIdConnectParameterNames.ClientSecret, notification.Options.ClientSecret},
                                    {OpenIdConnectParameterNames.Code, notification.ProtocolMessage.Code},
                                    {OpenIdConnectParameterNames.GrantType, "authorization_code"},
                                    {OpenIdConnectParameterNames.ResponseType, "token"},
                                    {OpenIdConnectParameterNames.RedirectUri, notification.Options.RedirectUri}
                               });

                                var response = await client.SendAsync(request, notification.Request.CallCancelled);
                                response.EnsureSuccessStatusCode();

                                var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

                                // Add the access token to the returned ClaimsIdentity to make it easier to retrieve.
                                notification.AuthenticationTicket.Identity.AddClaim(new Claim(
                                   type: OpenIdConnectParameterNames.AccessToken,
                                   value: payload.Value<string>(OpenIdConnectParameterNames.AccessToken)));
                            }
                        }
                    }
                });
        }
    }
}

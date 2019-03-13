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

namespace OpenID_Sample
{
    public partial class Startup {

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301883
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = "a79acc19c5ddd565007918d7e3a61cd490de86e5ec9179f445802285b4750999",
                    ClientSecret = "214e85448c1f3c276797ab49e3817804c9555a39b4cc025fa00a135206d8b19d",
                    Authority = "https://oauth2id.dev/",
                    RequireHttpsMetadata = true,
                    ResponseType = "code",
                    Scope = "openid",
                    RedirectUri = "https://localhost:44352/",
                });
        }
    }
}

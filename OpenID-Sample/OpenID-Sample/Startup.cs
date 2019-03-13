using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OpenID_Sample.Startup))]
namespace OpenID_Sample
{
    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}

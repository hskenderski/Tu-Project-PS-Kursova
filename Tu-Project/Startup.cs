using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Tu_Project.Startup))]
namespace Tu_Project
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

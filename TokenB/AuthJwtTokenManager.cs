using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TokenB;
using TokenB.ClaimRequirements;

namespace TokenB
{
    public class AuthJwtTokenManager
    {
        public const int ExpireDays = 30;

        public const string Issuer = "https://awesome-website.com";

        public const string Audience = "audience";

        public const string SubdomainKey = "Subdomain";

        private const string Key = "supersecret_secretkey!12345";

        public static SecurityKey GetSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
        }

        public const string ValidSubdomainPolicy = "CorrectSubdomainOnly";
    }
}

namespace TokenB.ClaimRequirements
{
    public class ValidSubdomainRequirement : IAuthorizationRequirement
    {
        public string ClaimSubdomainKey { get; private set; }

        public ValidSubdomainRequirement(string subdomainKey)
        {
            this.ClaimSubdomainKey = subdomainKey;
        }
    }

    public class ValidSubdomainHandler
        : AuthorizationHandler<ValidSubdomainRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            ValidSubdomainRequirement requirement)
        {
            if (context.Resource is AuthorizationFilterContext filterContext)
            {
                var httpContext = filterContext.HttpContext;

                var env = httpContext.RequestServices.GetService<IHostingEnvironment>();
                if (env.IsDevelopment())
                {
                    context.Succeed(requirement);
                }
                else
                {
                    string subdomainFromToken = context.User.FindFirstValue(requirement.ClaimSubdomainKey);
                    var host = httpContext.Request.Host;

                    // todo: check if host includes/starts with subdomain

                    if (subdomainFromToken == "subdomain1")
                    {
                        context.Succeed(requirement);
                    }
                }
            }

            return Task.CompletedTask;
        }
    }
}



namespace Microsoft.Extensions.DependencyInjection
{
    /*
     * Required nuget packages: 
     * - System.IdentityModel.Tokens.Jwt
     * - Microsoft.AspNetCore.Authentication.JwtBearer
     */
    public static class IServiceCollectionExtensions
    {
        /*
         * 1) In Startup.ConfigureServices invoke before services.AddMvc(): 
         *      services.AddJwtBearerAuthentication();
         * 
         * 2) Also in Startup.Configure invoke app.UseAuthentication() before app.UseMvc():
         *      app.UseAuthentication();
         */

        public static void AddJwtBearerAuthentication(this IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = AuthJwtTokenManager.Issuer,

                        ValidateAudience = true,
                        ValidAudience = AuthJwtTokenManager.Audience,
                        ValidateLifetime = true,

                        IssuerSigningKey = AuthJwtTokenManager.GetSecurityKey(),
                        ValidateIssuerSigningKey = true
                    };
                });

            services.AddSingleton<IAuthorizationHandler, ValidSubdomainHandler>();

            services.AddAuthorization(options =>
            {
                options.AddPolicy(AuthJwtTokenManager.ValidSubdomainPolicy, 
                    policy => policy.RequireClaim(AuthJwtTokenManager.SubdomainKey)
                                    .AddRequirements(new ValidSubdomainRequirement(AuthJwtTokenManager.SubdomainKey)));
            });
        }
    }
}

namespace System.Security.Claims
{
    public static class ClaimsIdentityExtensions
    {
        public static string GetJwtToken(this ClaimsIdentity idenitity)
        {
            var key = AuthJwtTokenManager.GetSecurityKey();

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: AuthJwtTokenManager.Issuer,
                audience: AuthJwtTokenManager.Audience,
                notBefore: DateTime.UtcNow,
                claims: idenitity.Claims,
                expires: DateTime.UtcNow.AddDays(AuthJwtTokenManager.ExpireDays),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

namespace System.Security.Claims
{
    public static class ClaimsPrincipalExtensions
    {
        public static string GetUserId(this ClaimsPrincipal user)
        {
            return user.FindFirstValue(ClaimTypes.NameIdentifier);
        }
    }
}

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using TokenB;

namespace TokenB
{
    public class AuthJwtTokenManager
    {
        public const int ExpireDays = 30;

        public const string Issuer = "https://awesome-website.com";

        public const string Audience = "subdomain-name";

        private const string Key = "supersecret_secretkey!12345";

        public static SecurityKey GetSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key));
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

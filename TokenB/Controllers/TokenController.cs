using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace TokenB.Controllers
{
    public class AuthenticatedUserInfoJsonModel
    {
        public string UserId { get; internal set; }
        public string Name { get; internal set; }
        public string FullName { get; internal set; }
        public string Subdomain { get; internal set; }
        public string Token { get; internal set; }
    }

    [Authorize(Policy = AuthJwtTokenManager.ValidSubdomainPolicy)]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration Configuration;

        public TokenController(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        
        [AllowAnonymous]
        [HttpPost("token")]
        public IActionResult Create(string username, string password)
        {
            // example
            if (username != "admin" || password != "admin")
            {
                return BadRequest("Could not verify username and password");
            }

            /*
            User user = await _userRepository.GetUser(credentials.Email, credentials.Password);
            if (user == null)
            {
                return BadRequest();
            }
            */

            string userId = "A123";
            string name = "Vlad L.";
            string[] roles = { "role1", "role2" };
            string subdomain = Request.Host.Host.Split('.').FirstOrDefault();

            if (subdomain == Request.Host.Host)
            {
                subdomain = "n/a";
            }

            var identity = GetClaimsIdentity(userId, name, roles, subdomain);            

            return Ok(new AuthenticatedUserInfoJsonModel
            {
                UserId = userId,
                Name = name,
                FullName = "Stereo Vlad",
                Subdomain = subdomain,
                Token = identity.GetJwtToken()
            });
        }


        [Authorize(Roles = "role1")]
        [HttpGet("test")]
        public object Test()
        {
            return new {
                UserId = User.GetUserId(),
                UserName = User.Identity.Name,
                Claims = User.Claims.Select(x => new {
                    x.Type,
                    x.Value
                })
            };
        }

        private ClaimsIdentity GetClaimsIdentity(string userId, string name, string[] roles, string subdomain)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, userId),
                new Claim(ClaimTypes.Name, name),
                new Claim(AuthJwtTokenManager.ClaimSubdomainKey, subdomain)
            };

            var claimsIdentity = new ClaimsIdentity(claims);

            claimsIdentity.AddClaims(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            return claimsIdentity;
        }
    }
}
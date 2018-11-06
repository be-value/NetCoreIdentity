using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace PluralsightIdentity
{
    public class PluralsightUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<PluralsightUser>
    {
        public PluralsightUserClaimsPrincipalFactory(UserManager<PluralsightUser> userManager, IOptions<IdentityOptions> optionsAccessor) : base(userManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(PluralsightUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);
            identity.AddClaim(new Claim("locale", user.Locale));
            return identity;
        }
    }
}

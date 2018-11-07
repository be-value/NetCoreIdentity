using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace PluralsightIdentity
{
    public class DoesNotContainPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser: class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var username = await manager.GetUserNameAsync(user);

            if (string.Equals(username, password, StringComparison.InvariantCultureIgnoreCase))
            {
                return IdentityResult.Failed(new IdentityError {Description = "Password cannot contain username"});
            }

            if (password.Contains("password", StringComparison.InvariantCulture))
            {
                return IdentityResult.Failed(new IdentityError {Description = "Password cannot contain 'password'"});
            }

            return IdentityResult.Success;
        }
    }
}

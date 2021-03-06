﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PluralsightIdentity.Models;

namespace PluralsightIdentity.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<PluralsightUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<PluralsightUser> _claimsPrincipalFactory;

        public HomeController(UserManager<PluralsightUser> userManager, IUserClaimsPrincipalFactory<PluralsightUser> claimsPrincipalFactory)
        {
            _userManager = userManager;
            _claimsPrincipalFactory = claimsPrincipalFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        #region Account Registration
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    user = new PluralsightUser
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        Email = model.UserName                        
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home",
                            new {token, email = user.Email}, Request.Scheme);
                        System.IO.File.WriteAllText("confirmationEmailLink.txt", confirmationEmail);
                    }
                    else
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }

                        return View();
                    }
                }

                return View("Success");
            }

            return View();
        }
        #endregion

        #region Email confirmation
        [HttpGet]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return View("Success");
                }
            }

            return View("Error");
        }
        #endregion

        #region login/logout
        [HttpGet]
        public IActionResult Login(string returnUrl = "")
        {
            var model = new LoginModel { ReturnUrl = returnUrl };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                // Check for lockout BEFORE checking the password
                if (user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    // no lockout, check password
                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        if (!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            ModelState.AddModelError("", "Email is not confirmed");
                            return View(model);
                        }

                        // password correct, reset access failed count for this user
                        await _userManager.ResetAccessFailedCountAsync(user);

                        // two factor authentication enabled?
                        if (await _userManager.GetTwoFactorEnabledAsync(user))
                        {
                            var validProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);

                            if (validProviders.Contains(_userManager.Options.Tokens.AuthenticatorTokenProvider))
                            {
                                if (!await TwoFactorRememberMe(user.Id))
                                {
                                    await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                        Store2FA(user.Id, _userManager.Options.Tokens.AuthenticatorTokenProvider, IdentityConstants.TwoFactorUserIdScheme));
                                    return RedirectToAction("TwoFactor");
                                }
                            }
                            else
                            {
                                if (validProviders.Contains("Email"))
                                {
                                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                                    System.IO.File.WriteAllText("email2sv.txt", token);

                                    await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                        Store2FA(user.Id, "Email", IdentityConstants.TwoFactorUserIdScheme));
                                    return RedirectToAction("TwoFactor");
                                }
                            }
                        }

                        // authenticate!
                        var principal = await _claimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                        // return to previously requested page
                        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                        {
                            return Redirect(model.ReturnUrl);
                        }

                        return RedirectToAction("Index");
                    }
                    else
                    {
                        // password incorrect, increase access failed count for this user
                        await _userManager.AccessFailedAsync(user);

                        // to prevent brute force attacks, inform the user that he/she is locked out
                        if (await _userManager.IsLockedOutAsync(user))
                        {
                            // Send email to the user, notifying them of the lockout
                        }
                    }
                }

                ModelState.AddModelError("", "Invalid UserName or Password");
            }

            return View(model);
        }
        #endregion

        #region Forgot/Reset password
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetUrl = Url.Action("ResetPassword", "Home", new {token, email = user.Email }, Request.Scheme);
                    System.IO.File.WriteAllText("resetlink.txt", resetUrl);
                }
                else
                {
                    // email user and inform them that they do not have an account
                }

                return View("Success");
            }

            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            return View(new ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                    }

                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        // revoke lockout by setting the end date to now - the user is now able to login again with its new password
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                    }

                    return View("Success");
                }

                ModelState.AddModelError("", "Invalid Request");
            }

            return View();
        }
        #endregion

        #region Two Factor Authentication
        [HttpGet]
        public IActionResult TwoFactor()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactorModel model)
        {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Your login request has expired, please start over.");
                return View();
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));

                if (user != null)
                {
                    var isValid = await _userManager.VerifyTwoFactorTokenAsync(user,
                        result.Principal.FindFirstValue("amr"), model.Token);

                    if (isValid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

                        var claimsPrincipal = await _claimsPrincipalFactory.CreateAsync(user);
                        var appProps = new AuthenticationProperties {IsPersistent = true};

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal, appProps);

                        var rememberMeProps = new AuthenticationProperties {IsPersistent = true};
                        var rememberMePrincipal = Store2FA(user.Id, _userManager.Options.Tokens.AuthenticatorTokenProvider, IdentityConstants.TwoFactorRememberMeScheme);
                        await HttpContext.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme, rememberMePrincipal, rememberMeProps);

                        return RedirectToAction("Index");
                    }

                    ModelState.AddModelError("", "Invalid token");
                    return View();
                }

                ModelState.AddModelError("", "Invalid Request");
            }

            return View();
        }


        [HttpGet]
        [Authorize]
        public async Task<IActionResult> RegisterAuthenticator()
        {
            // Get pluralsight user based on authenticated principal
            var user = await _userManager.GetUserAsync(User);
            // Retrieve the authenticator key for this user
            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            // if user did not register before, there is no authenticator key, lets create it
            if (authenticatorKey == null)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            return View(new RegisterAuthenticatorModel {AuthenticatorKey = authenticatorKey});
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> RegisterAuthenticator(RegisterAuthenticatorModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

            if (!isValid)
            {
                ModelState.AddModelError("", "Code is invalid");
                return View(model);
            }

            // now enable two factor authentication for this user because he successfully registered an authenticator
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return View("Success");
        }

        private async Task<bool> TwoFactorRememberMe(string userId)
        {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme);
            if (!result.Succeeded)
            {
                return false;
            }

            var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));
            if (user == null)
            {
                return false;
            }

            return user.Id == userId;
        }

        // ReSharper disable once InconsistentNaming
        private static ClaimsPrincipal Store2FA(string userId, string provider, string scheme)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                new Claim("amr", provider)
            }, scheme);

            return new ClaimsPrincipal(identity);
        }
        #endregion

        #region External identity provider (google, microsoft etc.)

        [HttpGet]
        public IActionResult ExternalLogin(string provider)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("ExternalLoginCallback"),
                Items = {{"scheme", provider}}
            };
            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            var externalUserId = result.Principal.FindFirstValue("sub")
                                 ?? result.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
                                 ?? throw new Exception("Cannot find external user id");
            var provider = result.Properties.Items["scheme"];
            var user = await _userManager.FindByLoginAsync(provider, externalUserId);

            if (user == null)
            {
                var email = result.Principal.FindFirstValue("email")
                            ?? result.Principal.FindFirstValue(ClaimTypes.Email);

                if (email != null)
                {
                    user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        user = new PluralsightUser
                            {UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = false};
                        // create user without a password - it is provided by the external identity provider
                        await _userManager.CreateAsync(user);
                    }

                    await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, externalUserId, provider));
                }
            }

            if (user == null)
            {
                return View("Error");
            }

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            var claimsPrincipal = await _claimsPrincipalFactory.CreateAsync(user);
            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

            return RedirectToAction("Index");
        }
        #endregion
    }
}

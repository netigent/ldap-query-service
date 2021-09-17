# ldapquery
LDAP Library for .netcore allowing you to Authenticate with LDAP Query Users and Groups

# How to use

Initially thanks for considering using this library - we hope that it gives you some benefits.
In terms of using the Library the following should get you up and running quickly

LDAP settings in appSettings.json

  "LDAP": {
    "FullDNS": "myorg.com",
    "Port": 636,
    "SearchBase": "OU=AADDC Users,DC=myorg,DC=com",
    "UseSSL": false,
    "UserLoginDomain": "MyDefaultDomain (Optional)"
  },
  
In Startup.cs
Register the service into the DI 

public void ConfigureServices(IServiceCollection services)
{
	 //Inject LDAP provider
	services.Configure<LdapConfig>(Configuration.GetSection(LdapConfig.Section));
	services.AddSingleton<ILdapQueryService, LdapQueryService>();
}

Utilising in the controller class, the below should give you a good example of how to use the Library

using System;
using Netigent.LdapQuery;
using Netigent.LdapQuery.Enum;
using Netigent.LdapQuery.Models;
using Microsoft.Extensions.Options;

namespace MyOrg.CompanyWeb.Controllers
{
	public class AuthController : Controller
	{
		//Assign ILdapQueryService to a readonly field;
		private readonly ILdapQueryService _authService;
		private readonly string AdminCn = "CN=SecretAdminGroup,OU=Users,DC=myorg,DC=com"

		//Inject the ILdapQueryService
		public AuthController(ILdapQueryService authService, IOptions<LdapConfig> ldapOptions)
		{
			_ldapOptions = ldapOptions;
			_authService = authService;
		}

		[HttpPost]
		public ActionResult LdapSignIn()
		{
			
			string domain = _ldapOptions.Value.UserLoginDomain;
			string username = Convert.ToString(Request.Form["txtUserId"]);
			string password = Convert.ToString(Request.Form["txtPassword"]);

			//Attempt Login using ILdapQueryService - will return true if Logged In / false if it couldnt bind
			if(!_authService.Login(LdapQueryAttribute.sAMAccountName, domain, username, password, out string loginErrorMessage))
			{
				TempData["UserMessage"] = loginErrorMessage;
				_logger.LogInformation($"Ldap Authentication: Failed for {username} - {loginErrorMessage}");
				return Redirect("/Failed");
			}

			//Get the User as LdapUser
			LdapUser ldapUser = _authService.GetUser();

			//Check the user is in the AD group filter AdminCn
			if(!_authService.MemberOf(LdapQueryAttribute.distinguishedName, AdminCn))
			{
				_logger.LogError(null, $"Ldap Authentication: User Not Allowed {username}, not in GroupFilter {AdminCn}");
				return RedirectToAction("Index", "Error", new { errorMessage = $"{user.FirstName} your account isn't in the Group for this website. Please contact the system administrator." });
			}
		}
	}
}

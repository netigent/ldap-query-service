# LdapQueryService
LDAP Library for .netcore allowing you to Authenticate, Query Users and Groups, check membership.

# How to use

Initially thanks for considering using this library - we hope that it gives you some benefits.
In terms of using the Library the following should get you up and running quickly

# Version Changes
**1.0.16** Added LDAP Functionality
***ResetUserLDAPPassword***: The ability in Windows Directory to Reset Password, must use serviceAccount (adminAccount), and serviceKey (adminPassword)
***Login***: Updated to allow login via Email attribute, requires serviceAccount (adminAccount), and serviceKey (adminPassword) as email may differ from UPN

**1.0.3** Extended the user/person query result to give extra properties
***Login Related***: LastLogon, LogonCount, LockoutTime, PwdLastSet 
***Job Related***: ManagerCn, Company, EmployeeID, JobTitle, Department 
***Address Information***: OfficeName, Street, City, State, Country, ZipPostalCode, OfficePhone, MobilePhone 

**1.0.2** Adding new field "AzureObjectId" (msDS-aadObjectId), for User/Person based objects, the property **msDS-aadObjectId** matches **OID** property in the JWT tokens issued by Azure OIDC, where the same ActiveDirectory is being used

### LDAP settings in **appSettings.json**

```
  "LDAP": {
    "FullDNS": "myorg.com",
    "Port": 636,
    "SearchBase": "OU=AADDC Users,DC=myorg,DC=com",
    "UseSSL": false,
    "UserLoginDomain": "MyDefaultDomain",				// (Optional)
	"MaxTries": 1,										// (Optional) Number of times to try logging, ONLY if LDAP reports unavailable, due to outage
	"RetryDelayMs": 300,								// (Optional) If retrying, how long to wait in MS
    "ServiceAccount": "mydomain\specialLdapAccount",	// (Optional) Not directly used by Nuget, Handy for use in your project via DI, you provide this by other ways if you wish
    "ServiceKey": "myserviceaccountpassword1123132"		// (Optional) Not directly used by Nuget, Handy for use in your project via DI, you provide this by other ways if you wish
  },
```
  
### Registering In **Startup.cs**
Register the service into the DI 
```
public void ConfigureServices(IServiceCollection services)
{
	 //Inject LDAP provider
	services.Configure<LdapConfig>(Configuration.GetSection(LdapConfig.Section));
	services.AddSingleton<ILdapQueryService, LdapQueryService>();
}
```

### Usage in a Controller Example
Utilising in the controller class, the below should give you a good example of how to use the Library

```
using System;
using Netigent.Utils.Ldap;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using Microsoft.Extensions.Options;

namespace MyOrg.CompanyWeb.Controllers
{
	public class AuthController : Controller
	{
		//Assign to readonly field;
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

			//Attempt Login - will return true if Logged In
			if(!_authService.Login(domain, username, password, out string loginErrorMessage))
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
```

using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap
{
    public partial class LdapQueryService
    {
        /// <inheritdoc />
        public LdapResult<LdapUser> UserLogin(string username, string password, string domain = "")
        {
            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return foundUserResult;
            }

            // Users Connection
            LdapConnection userConnection = BuildConnection();
            LdapResult loginResult = BindConnection(new NetworkCredential(
                userName: foundUserResult.Data.SamAccountName.GetPlainUsername(),
                password: password,
                domain: _config.UserLoginDomain),
                userConnection);

            if (loginResult.Success)
            {
                // Tidy the user connection.
                userConnection.Dispose();

                // Return result
                return new LdapResult<LdapUser>
                {
                    Success = foundUserResult.Success,
                    Message = foundUserResult.Message,
                    Data = foundUserResult.Data,
                };
            }

            // Return minimal failure, no user account
            return new LdapResult<LdapUser>
            {
                Success = loginResult.Success,
                Message = loginResult.Message,
            };
        }

        /// <inheritdoc />
        public IList<LdapUser>? GetUsers()
        {
            if (!_hasServiceAccount)
            {
                return null;
            }

            IList<LdapUser> results = new List<LdapUser>();
            foreach (SearchResultEntry r in SearchLdap(string.Format(LdapFilter.AllUsers), SupportedAttributes.User))
            {
                results.Add(r.TofoundUserResult());
            }

            return results;
        }

        /// <inheritdoc />
        public LdapResult<LdapUser> GetUser(string username)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult<LdapUser>
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(username))
            {
                return new LdapResult<LdapUser>
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Lets figure the username
            LdapUser? user = null;

            // Is this an email if so do we have a serviceAccount?
            if (username.Contains("@"))
            {
                // Attempting to find via UPN
                var result = SearchLdap(string.Format(LdapFilter.FindUserByUpn, username), SupportedAttributes.User);
                if (result.Count > 0)
                {
                    user = result[0].TofoundUserResult();
                }

                else
                {
                    // Try Email
                    result = SearchLdap(string.Format(LdapFilter.FindUserByEmail, username), SupportedAttributes.User);
                    if (result.Count > 0)
                    {
                        user = result[0].TofoundUserResult();
                    }
                }
            }

            // Is it a CN pattern?
            if (user == null && username.Contains("DC="))
            {
                // Attempting to find via DN
                var result = SearchLdap(string.Format(LdapFilter.FindUserByDn, username), SupportedAttributes.User);
                if (result.Count > 0)
                {
                    user = result[0].TofoundUserResult();
                }
            }

            // Lets spilt and attempt to find by SAM
            if (user == null)
            {
                // Attempting to find via DN
                var result = SearchLdap(string.Format(LdapFilter.FindGroupBySam, username), SupportedAttributes.User);
                if (result.Count > 0)
                {
                    user = result[0].TofoundUserResult();
                }
            }

            // Lets try AzureId / ObjectId
            if (user == null && Guid.TryParse(username, out Guid userId) == true)
            {
                return GetUser(userId);
            }

            if (user != null)
            {
                return new LdapResult<LdapUser>
                {
                    Success = true,
                    Data = user,
                    Message = "Found User",
                };
            }


            return new LdapResult<LdapUser>
            {
                Message = $"Couldnt find '{username}', checked UPN, Email, Dn and SAM"
            };
        }

        /// <inheritdoc />
        public LdapResult<LdapUser> GetUser(Guid userId)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult<LdapUser>
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (userId == default)
            {
                return new LdapResult<LdapUser>
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Lets figure the username
            LdapUser? user = null;

            var result = SearchLdap(string.Format(LdapFilter.FindUserByAzureIdOrObjectId, userId.ToString(), userId.ToBinaryString()), SupportedAttributes.User);
            if (result.Count > 0)
                user = result[0].TofoundUserResult();

            if (user != null)
            {
                return new LdapResult<LdapUser>
                {
                    Success = true,
                    Data = user,
                    Message = "Found User",
                };
            }

            return new LdapResult<LdapUser>
            {
                Message = $"Couldnt find '{userId.ToString()}', checked AzureId and ObjectId"
            };
        }

        /// <inheritdoc />
        public async Task<LdapResult> UpsertUserAsync(
            string username,
            string email,
            string displayName,
            string setPassword = "",
            string company = "",
            string department = "",
            string office = "",
            string jobTitle = "",
            string managerDn = "",
            string mobile = "",
            string street = "",
            string city = "",
            string zip = ""
            )
        {
            // Init Checks - Core Fields
            if (username.Length == 0 || email.Length == 0 || displayName.Length == 0)
            {
                return new LdapResult
                {
                    Message = $"Core Fields Required: username, email, displayName"
                };
            }

            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);

            // New Account Checks - Password
            if (!(foundUserResult?.Success ?? false) && !setPassword.IsValidPassword())
            {
                return new LdapResult { Message = "New Account Password - Doesn't meet complexity requirements" };
            }

            // Set attributes for the user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.DisplayName, displayName),
                new DirectoryAttribute(LdapAttribute.UserPrincipalName, username),
                new DirectoryAttribute(LdapAttribute.SAMAccountName, username.GetPlainUsername()),
            };

            // Company
            if (company?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Company, company));
            if (department?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Department, department));
            if (jobTitle?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.JobTitle, jobTitle));

            // About
            if (office?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.OfficeName, office));

            // Location
            if (street?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Street, street));
            if (city?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.City, city));
            if (zip?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.ZipPostalCode, zip));

            // Contact
            if (mobile?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.MobilePhone, mobile));
            if (email?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Mail, email));

            // Manager
            if (managerDn?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.ManagerDn, managerDn));

            string dnName = !foundUserResult.Success || foundUserResult.Data == null
                ? $"CN={displayName},{_config.SearchBase}"
                : foundUserResult.Data.DistinguishedName;

            // Perform Operation
            var saveResult = SaveLdap(dnName, LdapObjectType.User, directoryAttributes);

            // Failover to Azure Graph Library
            if (!saveResult.Success && saveResult.Message.Contains(LdapWarnings.AzureCloud) && _hasAzureGraph)
            {
                // var graphSaveResult = await _azureGraph.UpsertUserAsync();
                var gr = directoryAttributes.ToGraphRequest(setPassword, true);
                var graphUpsertResult = await _azureGraph.UpsertUserAsync(gr, foundUserResult?.Data);

                return new LdapResult
                {
                    Success = graphUpsertResult.Success,
                    Message = graphUpsertResult.Message + ", via Graph",
                };
            }

            // Do we need to reset LDAP password
            if (setPassword?.Length > 0 && saveResult.Success)
            {
                var passwordResult = await ResetPasswordAsync(dnName, setPassword);

                return new LdapResult
                {
                    Success = passwordResult.Success && saveResult.Success,
                    Message = saveResult.Message + ", " + passwordResult.Message,
                };
            }

            return saveResult;
        }

        /// <inheritdoc />
        public async Task<LdapResult> ResetPasswordAsync(string username, string newPassword)
        {
            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return new LdapResult { Message = foundUserResult.Message };
            }

            if (!newPassword.IsValidPassword())
            {
                return new LdapResult { Message = "Doesn't meet complexity requirements" };
            }

            string ldapPath = $"{_fullLdapPath}/{_config.SearchBase}";
            string serviceAccount = $"{_config.UserLoginDomain}\\{_config.ServiceAccount.GetPlainUsername()}";
            string filter = string.Format(LdapFilter.FindUserByDn, foundUserResult.Data.DistinguishedName);

            const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
            DirectoryEntry searchRoot = null;
            DirectorySearcher searcher = null;
            DirectoryEntry userEntry = null;

            try
            {
                searchRoot = new DirectoryEntry(ldapPath,
                    serviceAccount, _config.ServiceKey, authenticationTypes);

                searcher = new DirectorySearcher(searchRoot);
                searcher.Filter = filter;
                searcher.SearchScope = System.DirectoryServices.SearchScope.Subtree;
                searcher.CacheResults = false;

                System.DirectoryServices.SearchResult searchResult = searcher.FindOne();
                if (searchResult == null)
                {
                    return new LdapResult
                    {
                        Message = $"Failed: Didn't find {foundUserResult.Data.DistinguishedName} in {_config.SearchBase}"
                    };
                }

                userEntry = searchResult.GetDirectoryEntry();

                userEntry.Invoke("SetPassword", new object[] { newPassword });
                userEntry.CommitChanges();

                Console.WriteLine($"Password set '{newPassword}'");

                return new LdapResult
                {
                    Success = true,
                    Message = $"Password Reset"
                };
            }
            catch (Exception ex)
            {
                // Try Azure if cant connect
                if (ex.Message.Contains(LdapWarnings.ServerNotOpertational) && _hasAzureGraph)
                {
                    var graphResult = await _azureGraph.UpdatePasswordAsync(
                        userId: foundUserResult.Data.AzureOrObjectID,
                        password: newPassword);

                    return graphResult;
                }

                if (ex.Message.Contains("800708C5"))
                {
                    return new LdapResult
                    {
                        Message = $"Password Requirements: {ex.Message}"
                    };
                }
                else
                {
                    return new LdapResult
                    {
                        Message = $"Password Issue: {ex.Message}"
                    };
                }
            }
            finally
            {
                if (userEntry != null) userEntry.Dispose();
                if (searcher != null) searcher.Dispose();
                if (searchRoot != null) searchRoot.Dispose();
            }
        }

        /// <inheritdoc />
        public async Task<LdapResult> DisableUserAsync(string username)
        {

            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return new LdapResult { Message = foundUserResult.Message };
            }

            // Force to bit
            UserAccountControl userAccountControl = (UserAccountControl)foundUserResult.Data.UserAccountControl;

            // This gets a comma separated string of the flag names that apply.
            string userAccountControlFlagNames = userAccountControl.ToString();

            // Check if account is already disabled
            bool isAccountDisabled = (userAccountControl & UserAccountControl.ACCOUNTDISABLE) == UserAccountControl.ACCOUNTDISABLE;

            if (isAccountDisabled)
            {
                return new LdapResult
                {
                    Success = true,
                    Message = "Account is already disabled",
                };
            }

            // Disable the account by adding the ACCOUNTDISABLE flag
            UserAccountControl newUserAccountControl = userAccountControl | UserAccountControl.ACCOUNTDISABLE;

            // Set the new userAccountControl value
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.UserAccountControl, ((int)newUserAccountControl).ToString()), // Modify userAccountControl to disable account
            };

            // Attempt LDAP Reset
            var saveResult = SaveLdap(foundUserResult.Data.DistinguishedName, LdapObjectType.User, directoryAttributes);

            // Failover to Azure Graph Library
            if (!saveResult.Success && saveResult.Message.Contains(LdapWarnings.AzureCloud) && _hasAzureGraph)
            {
                var graphSaveResult = await _azureGraph.SetAccountEnabledAsync(foundUserResult.Data, false);
                return graphSaveResult;
            }

            return saveResult;
        }

        /// <inheritdoc />
        public async Task<LdapResult> EnableUserAsync(string username)
        {
            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return new LdapResult { Message = foundUserResult.Message };
            }

            // Retrieve current userAccountControl flags
            UserAccountControl userAccountControl = (UserAccountControl)foundUserResult.Data.UserAccountControl;

            // Check if account is already enabled and unlocked
            bool isAccountDisabled = (userAccountControl & UserAccountControl.ACCOUNTDISABLE) == UserAccountControl.ACCOUNTDISABLE;
            bool isAccountLockedOut = (userAccountControl & UserAccountControl.LOCKOUT) == UserAccountControl.LOCKOUT;

            if (!isAccountDisabled && !isAccountLockedOut)
            {
                return new LdapResult
                {
                    Success = true,
                    Message = "Account is already enabled and unlocked",
                };
            }

            // Remove ACCOUNTDISABLE and LOCKOUT flags
            UserAccountControl newUserAccountControl = userAccountControl & ~UserAccountControl.ACCOUNTDISABLE & ~UserAccountControl.LOCKOUT;

            // Set the new userAccountControl value
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.UserAccountControl, ((int)newUserAccountControl).ToString()), // Enable and unlock account
            };

            // Attempt LDAP Reset
            var saveResult = SaveLdap(foundUserResult.Data.DistinguishedName, LdapObjectType.User, directoryAttributes);

            // Failover to Azure Graph Library
            if (!saveResult.Success && saveResult.Message.Contains(LdapWarnings.AzureCloud) && _hasAzureGraph)
            {
                var graphSaveResult = await _azureGraph.SetAccountEnabledAsync(foundUserResult.Data, true);
                return graphSaveResult;
            }

            return saveResult;
        }
    }
}

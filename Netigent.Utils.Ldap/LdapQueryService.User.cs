using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;

namespace Netigent.Utils.Ldap
{
    public partial class LdapQueryService
    {
        /// <inheritdoc />
        public LdapResult<LdapUser> UserLogin(string username, string password, string domain = "")
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return userResult;
            }

            // Users Connection
            LdapConnection userConnection = BuildConnection();
            LdapResult loginResult = BindConnection(new NetworkCredential(
                userName: GetPlainUsername(userResult.Data.SamAccountName),
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
                    Success = userResult.Success,
                    Message = userResult.Message,
                    Data = userResult.Data,
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
                results.Add(r.ToUserResult());
            }

            return results;
        }

        /// <inheritdoc />
        public LdapUser? GetUser(LdapQueryAttribute userQueryType, string userString)
            => GetUser(userQueryType, userString, null);

        /// <inheritdoc />
        public LdapResult UpsertUser(
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
            string description = "",
            string street = "",
            string city = "",
            string zip = ""
            )
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);

            string plainUsername = GetPlainUsername(username);

            // Set attributes for the user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.DisplayName, displayName),
                new DirectoryAttribute(LdapAttribute.UserPrincipalName, $"{plainUsername}@{_config.UserLoginDomain}"),
                new DirectoryAttribute(LdapAttribute.SAMAccountName, plainUsername),
            };

            // Company
            if (company?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Company, company));
            if (department?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Department, department));
            if (jobTitle?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.JobTitle, jobTitle));

            // About
            if (office?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.OfficeName, office));
            if (description?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Description, description));

            // Location
            if (street?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Street, street));
            if (city?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.City, city));
            if (zip?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.ZipPostalCode, zip));

            // Contact
            if (mobile?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.MobilePhone, mobile));
            if (email?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Mail, email));

            // Manager
            if (managerDn?.Length > 0) directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.ManagerDn, managerDn));

            string dnName = !userResult.Success || userResult.Data == null
                ? $"CN={displayName},{_config.SearchBase}"
                : userResult.Data.DistinguishedName;

            // Perform Operation
            var upsertResult = SaveLdap(dnName, LdapObjectType.User, directoryAttributes);

            if (setPassword?.Length > 0 && upsertResult.Success)
            {
                var passwordResult = ResetPassword(dnName, setPassword);

                return new LdapResult
                {
                    Success = passwordResult.Success && upsertResult.Success,
                    Message = upsertResult.Message + ", " + passwordResult.Message,
                };
            }

            return upsertResult;
        }

        /// <inheritdoc />
        public LdapResult ResetPassword(string username, string newPassword)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return new LdapResult { Message = userResult.Message };
            }

            if ((newPassword?.Length ?? 0) <= 8)
            {
                return new LdapResult { Message = "Password is less than 8 characters" };
            }

            string ldapPath = $"{_fullLdapPath}/{_config.SearchBase}";
            string serviceAccount = $"{_config.UserLoginDomain}\\{GetPlainUsername(_config.ServiceAccount)}";
            string filter = string.Format(LdapFilter.FindUserByDn, userResult.Data.DistinguishedName);

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

                SearchResult searchResult = searcher.FindOne();
                if (searchResult == null)
                {
                    return new LdapResult
                    {
                        Message = $"Failed: Didn't find {userResult.Data.DistinguishedName} in {_config.SearchBase}"
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
        public LdapResult DisableUser(string username)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return new LdapResult { Message = userResult.Message };
            }

            // Force to bit
            UserAccountControl userAccountControl = (UserAccountControl)userResult.Data.UserAccountControl;

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

            return SaveLdap(userResult.Data.DistinguishedName, LdapObjectType.User, directoryAttributes);
        }

        /// <inheritdoc />
        public LdapResult EnableAndUnlockUser(string username)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return new LdapResult { Message = userResult.Message };
            }

            // Retrieve current userAccountControl flags
            UserAccountControl userAccountControl = (UserAccountControl)userResult.Data.UserAccountControl;

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

            // Send the modification request to LDAP
            return SaveLdap(userResult.Data.DistinguishedName, LdapObjectType.User, directoryAttributes);
        }

        #region Internal
        private LdapUser? GetUser(LdapQueryAttribute userQueryType, string userString, LdapConnection? alternativeConnection = null)
        {
            if (!_hasServiceAccount)
            {
                return null;
            }

            var userQueryString = string.Empty;
            switch (userQueryType)
            {
                case LdapQueryAttribute.SamAccountName:
                    userQueryString = string.Format(LdapFilter.FindUserBySam, userString);
                    break;
                case LdapQueryAttribute.Dn:
                    userQueryString = string.Format(LdapFilter.FindUserByDn, userString);
                    break;
                case LdapQueryAttribute.ObjectId:
                    userQueryString = string.Format(LdapFilter.FindUserByGuid, userString);
                    break;
                case LdapQueryAttribute.DisplayName:
                    userQueryString = string.Format(LdapFilter.FindUserByDisplayname, userString);
                    break;
                case LdapQueryAttribute.Email:
                    userQueryString = string.Format(LdapFilter.FindUserByEmail, userString);
                    break;
                case LdapQueryAttribute.Upn:
                    userQueryString = string.Format(LdapFilter.FindUserByUpn, userString);
                    break;
                default:
                    return default;
            }

            var result = SearchLdap(userQueryString, SupportedAttributes.User);
            if (result.Count > 0)
                return result[0].ToUserResult();

            return default;
        }

        /// <summary>
        /// Supply either user.name, user.principal@mydomain.com, users.email@domain.com, uses ServiceAccount.
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private LdapResult<LdapUser> FindUser(string username)
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
                user = GetUser(LdapQueryAttribute.Upn, username);

                // Attempt to find via email.
                if (user == null) user = GetUser(LdapQueryAttribute.Email, username);
            }

            // Is it a CN pattern?
            if (user == null && username.Contains("DC="))
            {
                user = GetUser(LdapQueryAttribute.Dn, username);
            }

            // Lets spilt and attempt to find by SAM
            if (user == null)
            {
                user = GetUser(LdapQueryAttribute.SamAccountName, GetPlainUsername(username));
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
                Message = $"Couldnt find '{username}', checked UPN, Email, SAM"
            };
        }

        private string GetPlainUsername(string username)
        {
            // Determine the username
            return username.Contains("@") // If account has a @ e.g. john.bloggs@mycompany.com
                    ? username.Split('@')[0] // Take 1st part as possible username
                    : username.Contains("\\") // If user is presented as mycompany\john.bloggs
                        ? username.Split('\\')[1] // Take last part
                        : username; // Otherwise treat username as-is e.g. john.bloggs
        }

        #endregion
    }
}

using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;
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
                userName: $"{(domain?.Length > 0 ? domain : _config.UserLoginDomain)}\\{userResult.Data.SamAccountName}",
                password: password),
                userConnection);

            if (userResult.Success)
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
                Success = userResult.Success,
                Message = userResult.Message,
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
        public LdapResult UpsertUser(string username, string password, string email, string displayName, string managerDn = "")
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);

            // Set attributes for the user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.SAMAccountName, username),
                new DirectoryAttribute("userPassword", password),
                new DirectoryAttribute(LdapAttribute.DisplayName, displayName?.Length > 0 ? displayName : username),
                new DirectoryAttribute(LdapAttribute.UserPrincipalName,$"{username}@{_config.UserLoginDomain}"),
            };

            // Optional Attributes
            if (managerDn?.Length > 0)
            {
                directoryAttributes.Add(new DirectoryAttribute("manager", managerDn));
            }

            if (email?.Length > 0)
            {
                directoryAttributes.Add(new DirectoryAttribute(LdapAttribute.Mail, email));
            }

            // Update or Add?
            if (!userResult.Success || userResult.Data == null)
            {
                string dn = $"CN={displayName},{_config.SearchBase}";
                return AddLdap(dn, LdapObject.User, directoryAttributes);
            }
            else
            {
                return ModifyLdap(userResult.Data.DistinguishedName, directoryAttributes);
            }
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

            // Set attributes for the new user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.UserPassword, newPassword), // UserPassword is OpenLDAP and just string
                new DirectoryAttribute(LdapAttribute.UnicodePassword, $"\"{newPassword}\""), // UnicodePwd is Microsoft and is a quoted string
            };

            return ModifyLdap(userResult.Data.DistinguishedName, directoryAttributes);
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

            return ModifyLdap(userResult.Data.DistinguishedName, directoryAttributes);
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
            return ModifyLdap(userResult.Data.DistinguishedName, directoryAttributes);
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

            if (user == null)
            {
                // Determine the username
                string loginAsName = username.Contains("@") // If account has a @ e.g. john.bloggs@mycompany.com
                        ? username.Split('@')[0] // Take 1st part as possible username
                        : username.Contains("\\") // If user is presented as mycompany\john.bloggs
                            ? username.Split('\\')[1] // Take last part
                            : username; // Otherwise treat username as-is e.g. john.bloggs

                user = GetUser(LdapQueryAttribute.SamAccountName, loginAsName);
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

        #endregion
    }
}

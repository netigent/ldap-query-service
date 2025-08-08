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
            // Lets figure the username
            LdapUser? user = null;

            // Is this an email if so do we have a serviceAccount?
            if (username.Contains("@") && _hasServiceAccount)
            {
                // Attempting to find via mail
                user = GetUser(LdapQueryAttribute.mail, username);

                // Could be a servicePrincipal - lets remove the end as thats the domain part
                if (user == null)
                {
                    user = GetUser(LdapQueryAttribute.sAMAccountName, username.Split('@')[0]);
                }
            }

            // Determine the username
            string loginAsName = user != null
                ? user?.SamAccountName ?? string.Empty // If matching account was found, use that
                : username.Contains("@") // If no matching account - but has a @ e.g. john.bloggs@mycompany.com
                    ? username.Split('@')[0] // Take 1st part as possible username
                    : username.Contains("\\") // If user is presented as mycompany\john.bloggs
                        ? username.Split('\\')[1] // Take last part
                        : username; // Otherwise treat username as-is e.g. john.bloggs

            // Users Connection
            LdapConnection userConnection = BuildConnection();
            LdapResult userResult = BindConnection(new NetworkCredential(
                userName: $"{_config.UserLoginDomain}\\{loginAsName}",
                password: password),
                userConnection);

            if (userResult.Success)
            {
                // Figure out the UserAccount
                user = user ?? (_hasServiceAccount // No, but do you have the serviceAccount?
                        ? GetUser(LdapQueryAttribute.sAMAccountName, loginAsName) // Get Account using Service Account
                        : GetUser(LdapQueryAttribute.sAMAccountName, username, userConnection)); // Get Account with Users Own Connection

                // Tidy the user connection.
                userConnection.Dispose();

                // Return result
                return new LdapResult<LdapUser>
                {
                    Success = userResult.Success,
                    Message = userResult.Message,
                    Data = user,
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
            foreach (SearchResultEntry r in SearchLdap(string.Format(LdapFilter.AllUsers), AttributeList.User))
            {
                results.Add(r.ToUserResult());
            }

            return results;
        }

        /// <inheritdoc />
        public LdapUser? GetUser(LdapQueryAttribute userQueryType, string userString)
            => GetUser(userQueryType, userString, null);

        /// <inheritdoc />
        public LdapResult UpsertUser(string userName, string password, string email, string displayName, string managerDn = "")
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password))
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Does user exist?
            LdapUser? ldapUser = GetUser(LdapQueryAttribute.sAMAccountName, userName);

            // Set attributes for the user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.SAMAccountName, userName),
                new DirectoryAttribute("userPassword", password),
                new DirectoryAttribute(LdapAttribute.DisplayName, displayName?.Length > 0 ? displayName : userName),
                new DirectoryAttribute(LdapAttribute.UserPrincipalName,$"{userName}@{_config.UserLoginDomain}"),
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
            if (ldapUser == null)
            {
                string dn = $"CN={displayName},{_config.SearchBase}";
                return AddLdap(dn, LdapObject.User, directoryAttributes);
            }
            else
            {
                return ModifyLdap(ldapUser.DistinguishedName, directoryAttributes);
            }
        }

        /// <inheritdoc />
        public LdapResult ResetPassword(string username, string newPassword)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(newPassword))
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            LdapUser? ldapUser = GetUser(LdapQueryAttribute.sAMAccountName, username);
            if (ldapUser == null)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "User Not Found",
                };
            }

            // Set attributes for the new user
            IList<DirectoryAttribute> directoryAttributes = new List<DirectoryAttribute>()
            {
                new DirectoryAttribute(LdapAttribute.UserPassword, newPassword), // UserPassword is OpenLDAP and just string
                new DirectoryAttribute(LdapAttribute.UnicodePassword, $"\"{newPassword}\""), // UnicodePwd is Microsoft and is a quoted string
            };

            return ModifyLdap(ldapUser.DistinguishedName, directoryAttributes);
        }

        /// <inheritdoc />
        public LdapResult DisableUser(string username)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(username))
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            LdapUser? ldapUser = GetUser(LdapQueryAttribute.sAMAccountName, username);
            if (ldapUser == null)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "User Not Found",
                };
            }

            // Force to bit
            UserAccountControl userAccountControl = (UserAccountControl)ldapUser.UserAccountControl;

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

            return ModifyLdap(ldapUser.DistinguishedName, directoryAttributes);
        }

        /// <inheritdoc />
        public LdapResult EnableAndUnlockUser(string username)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(username))
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Find the user
            LdapUser? ldapUser = GetUser(LdapQueryAttribute.sAMAccountName, username);
            if (ldapUser == null)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = "User Not Found",
                };
            }

            // Retrieve current userAccountControl flags
            UserAccountControl userAccountControl = (UserAccountControl)ldapUser.UserAccountControl;

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
            return ModifyLdap(ldapUser.DistinguishedName, directoryAttributes);
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
                case LdapQueryAttribute.sAMAccountName:
                    userQueryString = string.Format(LdapFilter.FindUserBySam, userString);
                    break;
                case LdapQueryAttribute.distinguishedName:
                    userQueryString = string.Format(LdapFilter.FindUserByDn, userString);
                    break;
                case LdapQueryAttribute.objectGUID:
                    userQueryString = string.Format(LdapFilter.FindUserByGuid, userString);
                    break;
                case LdapQueryAttribute.displayName:
                    userQueryString = string.Format(LdapFilter.FindUserByDisplayname, userString);
                    break;
                case LdapQueryAttribute.mail:
                    userQueryString = string.Format(LdapFilter.FindUserByEmail, userString);
                    break;
                default:
                    return default;
            }

            var result = SearchLdap(userQueryString, AttributeList.User);
            if (result.Count > 0)
                return result[0].ToUserResult();

            return default;
        }

        #endregion
    }
}

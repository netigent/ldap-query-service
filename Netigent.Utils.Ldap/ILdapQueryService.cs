using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap
{
    public interface ILdapQueryService
    {
        /// <summary>
        /// Attempt to Bind as User.
        /// </summary>
        /// <param name="username">Supply either user.name, user.principal@mydomain.com, users.email@domain.com</param>
        /// <param name="password"></param>
        /// <param name="domain">Default Domain Override? e.g. MyWorkDomain - if you login as MyWorkDomain\user.name</param>
        /// <returns></returns>
        LdapResult<LdapUser> UserLogin(string username, string password, string domain = "");

        /// <summary>
        /// Gets All USers.
        /// </summary>
        /// <returns></returns>
        IList<LdapUser>? GetUsers();

        /// <summary>
        /// Get User by either user.name, user.principal@mydomain.com, users.email@domain.com, (uses ServiceAccount).
        /// </summary>
        /// <param name="username">user.name, user.principal@mydomain.com, users.email@domain.com</param>
        /// <returns></returns>
        LdapResult<LdapUser> GetUser(string username);

        /// <summary>
        /// Get User by either AzureId (msDS-aadObjectId) or objectGUID.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        LdapResult<LdapUser> GetUser(Guid userId);

        /// <summary>
        /// Enable User, will attempt to Unlock is simple LDAP (uses ServiceAccount).
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        Task<LdapResult> EnableUserAsync(string username);

        /// <summary>
        /// Disable User (uses ServiceAccount).
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        Task<LdapResult> DisableUserAsync(string username);

        /// <summary>
        /// Upsert User (uses ServiceAccount).
        /// </summary>
        /// <param name="upn">UserPrincipalName e.g. john.bloggs@netigent.co.uk</param>
        /// <param name="email">User Email (might be same as upn) e.g. john.bloggs@netigent.co.uk or johnb1@netigent.co.uk</param>
        /// <param name="displayName">John Bloggs</param>
        /// <param name="setPassword">Required for New Accounts, must met complexity requirements, usually 8+ chars and Cap, Small, Number and Special char.</param>
        /// <param name="company"></param>
        /// <param name="department"></param>
        /// <param name="office"></param>
        /// <param name="jobTitle"></param>
        /// <param name="managerDn"></param>
        /// <param name="mobile"></param>
        /// <param name="street"></param>
        /// <param name="city"></param>
        /// <param name="zip"></param>
        /// <returns></returns>
        Task<LdapResult> UpsertUserAsync(
            string upn,
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
            );

        /// <summary>
        /// Get Groups (uses ServiceAccount).
        /// </summary>
        /// <returns></returns>
        IList<LdapGroup>? GetGroups();

        /// <summary>
        /// Supply either GroupId (Object ID), DisplayName or Dn e.g CN=MY Development,OU=AADDC Users,DC=NETIGENT,DC=co (uses ServiceAccount).
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        LdapResult<LdapGroup> GetGroup(string group);

        /// <summary>
        /// Get Group by either AzureId (msDS-aadObjectId) or objectGUID  (uses ServiceAccount).
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>
        LdapResult<LdapGroup> GetGroup(Guid groupId);

        /// <summary>
        /// Checks if User is Group Member  (uses ServiceAccount).
        /// </summary>
        /// <param name="username"></param>
        /// <param name="group"></param>
        /// <returns></returns>
        bool IsMemberOf(string username, string group);

        /// <summary>
        /// Add User to Group  (uses ServiceAccount).
        /// </summary>
        /// <param name="username"></param>
        /// <param name="group"></param>
        /// <returns></returns>
        Task<LdapResult> AddToGroupAsync(string username, string group);

        /// <summary>
        /// Remove User to Group  (uses ServiceAccount).
        /// </summary>
        /// <param name="username"></param>
        /// <param name="groupname"></param>
        /// <returns></returns>
        Task<LdapResult> RemoveGroupAsync(string username, string group);

        /// <summary>
        /// Reset Password (uses ServiceAccount).
        /// </summary>
        /// <param name="upn"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        Task<LdapResult> ResetPasswordAsync(string username, string newPassword);
    }
}

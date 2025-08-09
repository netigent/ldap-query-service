using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;

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

        //Users
        IList<LdapUser>? GetUsers();
        LdapUser? GetUser(LdapQueryAttribute userQueryType, string userString);
        LdapResult EnableAndUnlockUser(string username);
        LdapResult DisableUser(string username);
        LdapResult UpsertUser(string username, string password, string email, string displayName, string managerDn = "");

        //Groups
        IList<LdapGroup>? GetGroups();
        LdapGroup? GetGroup(string groupName, LdapQueryAttribute groupQueryType = LdapQueryAttribute.DisplayName);
        bool MemberOf(string username, string groupName, LdapQueryAttribute groupQueryType = LdapQueryAttribute.DisplayName);

        //Generic
        IList<LdapGeneric> RunSearchQuery(string filter);

        LdapResult ResetPassword(string username, string newPassword);


    }
}

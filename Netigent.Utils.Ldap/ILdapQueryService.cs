using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap
{
    public interface ILdapQueryService
    {
        //Login Operation
        LdapResult<LdapUser> UserLogin(string username, string password, string domain = "");

        //Users
        IList<LdapUser>? GetUsers();
        LdapUser? GetUser(LdapQueryAttribute userQueryType, string userString);
        LdapResult EnableAndUnlockUser(string username);
        LdapResult DisableUser(string username);
        LdapResult UpsertUser(string userName, string password, string email, string displayName, string managerDn = "");

        //Groups
        IList<LdapGroup>? GetGroups();
        LdapGroup? GetGroup(LdapQueryAttribute groupQueryType, string groupString);

        //Memebership
        // bool MemberOf(LdapQueryAttribute groupQueryType, string groupString);
        bool MemberOf(LdapQueryAttribute userQueryType, string userString, LdapQueryAttribute groupQueryType, string groupString);

        //Generic
        IList<LdapGeneric> RunSearchQuery(string filter);

        LdapResult ResetPassword(string username, string newPassword);


    }
}

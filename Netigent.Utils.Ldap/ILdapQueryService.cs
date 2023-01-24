using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap
{
	public interface ILdapQueryService
	{
		//Login flag
		bool LoggedIn { get; }

		//Login Operation
		Task<LoginResult> Login(string username, string password);
		Task<LoginResult> Login(string domain, string username, string password, string serviceAccount = "", string serviceKey = "");

        //Users
        LdapUser GetUser();
		List<LdapUser> GetUsers();
		LdapUser GetUser(LdapQueryAttribute userQueryType, string userString);

		//Groups
        List<LdapGroup> GetGroups();
		LdapGroup GetGroup(LdapQueryAttribute groupQueryType, string groupString);

		//Memebership
		bool MemberOf(LdapQueryAttribute groupQueryType, string groupString);
		bool MemberOf(LdapQueryAttribute userQueryType, string userString, LdapQueryAttribute groupQueryType, string groupString);

		//Generic
		List<LdapGeneric> RunQuery(string filter);

        bool ResetUserLDAPPassword(string serviceAccount, string serviceKey, string container, string domainController, string userName, string newPassword, out bool unmetRequirements);
    }
}

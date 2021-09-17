using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap
{
	public interface ILdapQueryService
	{
		bool LoggedIn { get; }

		bool Login(string domain, string username, string password, out string errorMessage);

		LdapUser GetUser();

		List<LdapUser> GetUsers();
		LdapUser GetUser(LdapQueryAttribute userQueryType, string userString);

        List<LdapGroup> GetGroups();
		LdapGroup GetGroup(LdapQueryAttribute groupQueryType, string groupString);

		bool MemberOf(LdapQueryAttribute groupQueryType, string groupString);
		bool MemberOf(LdapQueryAttribute userQueryType, string userString, LdapQueryAttribute groupQueryType, string groupString);

		List<LdapGeneric> RunQuery(string filter);

	}
}

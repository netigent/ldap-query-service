﻿using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap
{
	public interface ILdapQueryService
	{
		//Login flag
		bool LoggedIn { get; }

		//Login Operation
		bool Login(string username, string password, out string errorMessage);
		bool Login(string domain, string username, string password, out string errorMessage, string serviceAccount = "", string serviceKey = "");

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

        bool ResetUserLDAPPassword(string dsName, string newPassword, string attributeName, out bool unmetRequirements);
    }
}

namespace Netigent.Utils.Ldap.Models
{
	public static class Constants
	{
		public static string memberOf = nameof(memberOf);
		public static string displayName = nameof(displayName);
		public static string sAMAccountName = nameof(sAMAccountName);
		public static string mail = nameof(mail);
		public static string objectsid = nameof(objectsid);
		public static string department = nameof(department);
		public static string objectCategory = nameof(objectCategory);
		public static string objectGUID = nameof(objectGUID);
		public static string userPrincipalName = nameof(userPrincipalName);
		public static string preferredLanguage = nameof(preferredLanguage);
		public static string member = nameof(member);
		public static string sn = nameof(sn);
		public static string givenName = nameof(givenName);

		public static string distinguishedName = nameof(distinguishedName);
		public static string whenChanged = nameof(whenChanged);
		public static string whenCreated = nameof(whenCreated);


		public static string filterAllGroups = "(&(objectClass=group))";
		public static string filterFindGroupByDisplayname = "(&(objectClass=group)(displayName={0}))";
		public static string filterFindGroupByDn = "(&(objectClass=group)(distinguishedName={0}))";
		public static string filterFindGroupBySam = "(&(objectClass=group)(sAMAccountName={0}))";
		public static string filterFindGroupByGuid = "(&(objectClass=group)(objectGUID={0}))";

		public static string filterAllUsers = "(&(objectCategory=person)(objectCategory=user))";
		public static string filterFindUserByDisplayname = "(&(objectClass=person)(objectCategory=user)(displayName={0}))";
		public static string filterFindUserByDn = "(&(objectClass=person)(objectCategory=user)(distinguishedName={0}))";
		public static string filterFindUserBySam = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))";
		public static string filterFindUserByGuid = "(&(objectClass=person)(objectCategory=user)(objectGUID={0}))";

	}
}

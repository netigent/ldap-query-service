using System;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap.Models
{
	public class LdapUser
	{
		public List<string> MemberOf { get; set; }
		public string DisplayName { get; set; }
		public string SamAccountName { get; set; }
		public string Mail { get; set; }
		public string ObjectSid { get; set; }
		public string Department { get; set; }
		public string ObjectCategory { get; set; }
		public Guid ObjectGUID { get; set; }
		public string UserPrincipalName { get; set; }
		public string PreferredLanguage { get; set; }
		public string Firstname { get; set; }
		public string Surname { get; set; }

		public string DistinguishedName { get; set; }
		public DateTime Created { get; set; }
		public DateTime Modified { get; set; }
	}
}
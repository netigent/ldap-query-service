using System;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap.Models
{
	public class LdapGroup
	{
		public string DisplayName { get; set; }
		public string SamAccountName { get; set; }
		public string ObjectSid { get; set; }
		public string ObjectCategory { get; set; }
		public Guid ObjectGUID { get; set; }
		public List<string> Members { get; set; }

		public string DistinguishedName { get; set; }
		public DateTime Created { get; set; }
		public DateTime Modified { get; set; }
	}
}

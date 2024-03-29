﻿using System;
using System.Collections.Generic;

namespace Netigent.Utils.Ldap.Models
{
	public class LdapGeneric
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
		public List<string> Members { get; set; }
		public string DistinguishedName { get; set; }
		public DateTime Created { get; set; }
		public DateTime Modified { get; set; }

		/// <summary>
		/// Azure ObjectGUID (msDS-aadObjectId)
		/// </summary>
		public Guid AzureObjectId { get; set; }
	}
}
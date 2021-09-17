using Netigent.Utils.Ldap.Models;
using System;
using System.DirectoryServices.Protocols;
using System.Security.Principal;

namespace Netigent.Utils.Ldap.Extensions
{
	public static class SearchResultEntryExtensions
	{
		public static LdapGeneric ToGenericResult(this SearchResultEntry searchResult)
		{
			if (searchResult == null || searchResult.Attributes.Count == 0)
				return default;

			LdapGeneric output = new();

			if (searchResult.Attributes.Contains(Constants.displayName))
				output.DisplayName = searchResult.Attributes[Constants.displayName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.mail))
				output.Mail = searchResult.Attributes[Constants.mail].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.department))
				output.Department = searchResult.Attributes[Constants.department].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectCategory))
				output.ObjectCategory = searchResult.Attributes[Constants.objectCategory].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.userPrincipalName))
				output.UserPrincipalName = searchResult.Attributes[Constants.userPrincipalName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.preferredLanguage))
				output.PreferredLanguage = searchResult.Attributes[Constants.preferredLanguage].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectGUID))
				output.ObjectGUID = searchResult.Attributes[Constants.objectGUID].ParseValue<Guid>();

			if (searchResult.Attributes.Contains(Constants.objectsid))
			{
#pragma warning disable CA1416 // Validate platform compatibility
				try
				{
					var acc = searchResult.Attributes[Constants.objectsid].ParseValue<SecurityIdentifier>();
					output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
				}
				catch
				{
					output.ObjectSid = null;
				}
#pragma warning restore CA1416 // Validate platform compatibility
			}

			if (searchResult.Attributes.Contains(Constants.memberOf))
			{
				var memberOfInfo = searchResult.Attributes[Constants.memberOf].ParseValues<string>();
				output.MemberOf = memberOfInfo;
			}

			if (searchResult.Attributes.Contains(Constants.sAMAccountName))
				output.SamAccountName = searchResult.Attributes[Constants.sAMAccountName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.distinguishedName))
				output.DistinguishedName = searchResult.Attributes[Constants.distinguishedName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.whenCreated))
				output.Created = searchResult.Attributes[Constants.whenCreated].ParseValue<DateTime>();

			if (searchResult.Attributes.Contains(Constants.whenChanged))
				output.Modified = searchResult.Attributes[Constants.whenChanged].ParseValue<DateTime>();


			if (searchResult.Attributes.Contains(Constants.member))
			{
				var members = searchResult.Attributes[Constants.member].ParseValues<string>();
				output.Members = members;
			}
			return output;
		}

		public static LdapUser ToUserResult(this SearchResultEntry searchResult)
		{
			if (searchResult == null || searchResult.Attributes.Count == 0)
				return default;

			LdapUser output = new();

			if (searchResult.Attributes.Contains(Constants.displayName))
				output.DisplayName = searchResult.Attributes[Constants.displayName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.mail))
				output.Mail = searchResult.Attributes[Constants.mail].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.department))
				output.Department = searchResult.Attributes[Constants.department].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectCategory))
				output.ObjectCategory = searchResult.Attributes[Constants.objectCategory].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.userPrincipalName))
				output.UserPrincipalName = searchResult.Attributes[Constants.userPrincipalName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.preferredLanguage))
				output.PreferredLanguage = searchResult.Attributes[Constants.preferredLanguage].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectGUID))
				output.ObjectGUID = searchResult.Attributes[Constants.objectGUID].ParseValue<Guid>();

			if (searchResult.Attributes.Contains(Constants.objectsid))
			{
#pragma warning disable CA1416 // Validate platform compatibility
				try
				{
					var acc = searchResult.Attributes[Constants.objectsid].ParseValue<SecurityIdentifier>();
					output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
				}
				catch
				{
					output.ObjectSid = null;
				}
#pragma warning restore CA1416 // Validate platform compatibility
			}

			if (searchResult.Attributes.Contains(Constants.memberOf))
			{
				var memberOfInfo = searchResult.Attributes[Constants.memberOf].ParseValues<string>();
				output.MemberOf = memberOfInfo;
			}

			if (searchResult.Attributes.Contains(Constants.distinguishedName))
				output.DistinguishedName = searchResult.Attributes[Constants.distinguishedName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.sAMAccountName))
				output.SamAccountName = searchResult.Attributes[Constants.sAMAccountName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.whenCreated))
				output.Created = searchResult.Attributes[Constants.whenCreated].ParseValue<DateTime>();

			if (searchResult.Attributes.Contains(Constants.whenChanged))
				output.Modified = searchResult.Attributes[Constants.whenChanged].ParseValue<DateTime>();

			if (searchResult.Attributes.Contains(Constants.sn))
				output.Surname = searchResult.Attributes[Constants.sn].ParseValue<string>();
			else
			{
				var lastBreak = output.DisplayName.LastIndexOf(" ");
				var surname = output.DisplayName.Substring(lastBreak + 1, output.DisplayName.Length - (lastBreak + 1));
				output.Surname = surname;
			}

			if (searchResult.Attributes.Contains(Constants.givenName))
				output.Firstname = searchResult.Attributes[Constants.givenName].ParseValue<string>();
			else
			{
				var lastBreak = output.DisplayName.LastIndexOf(" ");
				var firstname = output.DisplayName.Substring(0, lastBreak);
				output.Firstname = firstname;
			}

			if (searchResult.Attributes.Contains(Constants.sAMAccountName))
				output.SamAccountName = searchResult.Attributes[Constants.sAMAccountName].ParseValue<string>();

			return output;
		}

		public static LdapGroup ToGroupResult(this SearchResultEntry searchResult)
		{
			if (searchResult == null || searchResult.Attributes.Count == 0)
				return default;

			LdapGroup output = new();

			if (searchResult.Attributes.Contains(Constants.displayName))
				output.DisplayName = searchResult.Attributes[Constants.displayName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectCategory))
				output.ObjectCategory = searchResult.Attributes[Constants.objectCategory].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.objectGUID))
				output.ObjectGUID = searchResult.Attributes[Constants.objectGUID].ParseValue<Guid>();

			if (searchResult.Attributes.Contains(Constants.objectsid))
			{
#pragma warning disable CA1416 // Validate platform compatibility
				try
				{
					var acc = searchResult.Attributes[Constants.objectsid].ParseValue<SecurityIdentifier>();
					output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
				}
				catch
				{
					output.ObjectSid = null;
				}
#pragma warning restore CA1416 // Validate platform compatibility
			}

			if (searchResult.Attributes.Contains(Constants.member))
			{
				var members = searchResult.Attributes[Constants.member].ParseValues<string>();
				output.Members = members;
			}


			if (searchResult.Attributes.Contains(Constants.sAMAccountName))
				output.SamAccountName = searchResult.Attributes[Constants.sAMAccountName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.distinguishedName))
				output.DistinguishedName = searchResult.Attributes[Constants.distinguishedName].ParseValue<string>();

			if (searchResult.Attributes.Contains(Constants.whenCreated))
				output.Created = searchResult.Attributes[Constants.whenCreated].ParseValue<DateTime>();

			if (searchResult.Attributes.Contains(Constants.whenChanged))
				output.Modified = searchResult.Attributes[Constants.whenChanged].ParseValue<DateTime>();


			return output;
		}
	}
}

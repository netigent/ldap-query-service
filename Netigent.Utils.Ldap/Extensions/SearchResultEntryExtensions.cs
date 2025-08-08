using Netigent.Utils.Ldap.Constants;
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

            if (searchResult.Attributes.Contains(LdapAttribute.DisplayName))
                output.DisplayName = searchResult.Attributes[LdapAttribute.DisplayName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Mail))
                output.Mail = searchResult.Attributes[LdapAttribute.Mail].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Department))
                output.Department = searchResult.Attributes[LdapAttribute.Department].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectCategory))
                output.ObjectCategory = searchResult.Attributes[LdapAttribute.ObjectCategory].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.UserPrincipalName))
                output.UserPrincipalName = searchResult.Attributes[LdapAttribute.UserPrincipalName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.PreferredLanguage))
                output.PreferredLanguage = searchResult.Attributes[LdapAttribute.PreferredLanguage].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectGUID))
                output.ObjectGUID = searchResult.Attributes[LdapAttribute.ObjectGUID].ParseValue<Guid>();

            if (searchResult.Attributes.Contains(LdapAttribute.AzureObjectId))
                output.AzureObjectId = searchResult.Attributes[LdapAttribute.AzureObjectId].ParseValue<Guid>();

            if (searchResult.Attributes.Contains(LdapAttribute.Objectsid))
            {
#pragma warning disable CA1416 // Validate platform compatibility
                try
                {
                    var acc = searchResult.Attributes[LdapAttribute.Objectsid].ParseValue<SecurityIdentifier>();
                    output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
                }
                catch
                {
                    output.ObjectSid = null;
                }
#pragma warning restore CA1416 // Validate platform compatibility
            }

            if (searchResult.Attributes.Contains(LdapAttribute.MemberOf))
            {
                var memberOfInfo = searchResult.Attributes[LdapAttribute.MemberOf].ParseValues<string>();
                output.MemberOf = memberOfInfo;
            }

            if (searchResult.Attributes.Contains(LdapAttribute.SAMAccountName))
                output.SamAccountName = searchResult.Attributes[LdapAttribute.SAMAccountName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.DistinguishedName))
                output.DistinguishedName = searchResult.Attributes[LdapAttribute.DistinguishedName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenCreated))
                output.Created = searchResult.Attributes[LdapAttribute.WhenCreated].ParseValue<DateTime>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenChanged))
                output.Modified = searchResult.Attributes[LdapAttribute.WhenChanged].ParseValue<DateTime>();


            if (searchResult.Attributes.Contains(LdapAttribute.Member))
            {
                var members = searchResult.Attributes[LdapAttribute.Member].ParseValues<string>();
                output.Members = members;
            }
            return output;
        }

        public static LdapUser ToUserResult(this SearchResultEntry searchResult)
        {
            if (searchResult == null || searchResult.Attributes.Count == 0)
                return default;

            LdapUser output = new();

            if (searchResult.Attributes.Contains(LdapAttribute.DisplayName))
                output.DisplayName = searchResult.Attributes[LdapAttribute.DisplayName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Mail))
                output.Mail = searchResult.Attributes[LdapAttribute.Mail].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Department))
                output.Department = searchResult.Attributes[LdapAttribute.Department].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectCategory))
                output.ObjectCategory = searchResult.Attributes[LdapAttribute.ObjectCategory].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.UserPrincipalName))
                output.UserPrincipalName = searchResult.Attributes[LdapAttribute.UserPrincipalName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.PreferredLanguage))
                output.PreferredLanguage = searchResult.Attributes[LdapAttribute.PreferredLanguage].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectGUID))
                output.ObjectGUID = searchResult.Attributes[LdapAttribute.ObjectGUID].ParseValue<Guid>();

            if (searchResult.Attributes.Contains(LdapAttribute.AzureObjectId))
                output.AzureObjectId = searchResult.Attributes[LdapAttribute.AzureObjectId].ParseValue<Guid>();

            if (searchResult.Attributes.Contains(LdapAttribute.City))
                output.City = searchResult.Attributes[LdapAttribute.City].ParseValue<string>();
            if (searchResult.Attributes.Contains(LdapAttribute.Company))
                output.Company = searchResult.Attributes[LdapAttribute.Company].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Country))
                output.Country = searchResult.Attributes[LdapAttribute.Country].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.EmployeeID))
                output.EmployeeID = searchResult.Attributes[LdapAttribute.EmployeeID].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.JobTitle))
                output.JobTitle = searchResult.Attributes[LdapAttribute.JobTitle].ParseValue<string>();

            //Last Login
            if (searchResult.Attributes.Contains(LdapAttribute.LastLogon) || searchResult.Attributes.Contains(LdapAttribute.LastLogonTimestamp))
            {
                DateTime latestTimestamp;
                DateTime lastLogin = searchResult.Attributes.Contains(LdapAttribute.LastLogon) ? searchResult.Attributes[LdapAttribute.LastLogon].ParseValue<DateTime>() : default;
                DateTime lastLoginTimeStamp = searchResult.Attributes.Contains(LdapAttribute.LastLogonTimestamp) ? searchResult.Attributes[LdapAttribute.LastLogonTimestamp].ParseValue<DateTime>() : default;

                if (lastLoginTimeStamp != default && lastLogin != default)
                {
                    if (lastLoginTimeStamp > lastLogin)
                        latestTimestamp = lastLoginTimeStamp;
                    else
                        latestTimestamp = lastLogin;
                }
                else
                    latestTimestamp = lastLoginTimeStamp != default ? lastLoginTimeStamp : lastLogin;

                output.LastLogon = latestTimestamp != default ? lastLoginTimeStamp : null;
            }

            if (searchResult.Attributes.Contains(LdapAttribute.LockoutTime))
                output.LockoutTime = searchResult.Attributes[LdapAttribute.LockoutTime].ParseValue<long>();

            if (searchResult.Attributes.Contains(LdapAttribute.LogonCount))
                output.LogonCount = searchResult.Attributes[LdapAttribute.LogonCount].ParseValue<int>();

            if (searchResult.Attributes.Contains(LdapAttribute.ManagerCn))
                output.ManagerCn = searchResult.Attributes[LdapAttribute.ManagerCn].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.MobilePhone))
                output.MobilePhone = searchResult.Attributes[LdapAttribute.MobilePhone].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.OfficeName))
                output.OfficeName = searchResult.Attributes[LdapAttribute.OfficeName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Street))
                output.Street = searchResult.Attributes[LdapAttribute.Street].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.OfficePhone))
                output.OfficePhone = searchResult.Attributes[LdapAttribute.OfficePhone].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.State))
                output.State = searchResult.Attributes[LdapAttribute.State].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ZipPostalCode))
                output.ZipPostalCode = searchResult.Attributes[LdapAttribute.ZipPostalCode].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.PwdLastSet))
                output.PwdLastSet = searchResult.Attributes[LdapAttribute.PwdLastSet].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.Objectsid))
            {
#pragma warning disable CA1416 // Validate platform compatibility
                try
                {
                    var acc = searchResult.Attributes[LdapAttribute.Objectsid].ParseValue<SecurityIdentifier>();
                    output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
                }
                catch
                {
                    output.ObjectSid = null;
                }
#pragma warning restore CA1416 // Validate platform compatibility
            }

            if (searchResult.Attributes.Contains(LdapAttribute.MemberOf))
            {
                var memberOfInfo = searchResult.Attributes[LdapAttribute.MemberOf].ParseValues<string>();
                output.MemberOf = memberOfInfo;
            }

            if (searchResult.Attributes.Contains(LdapAttribute.DistinguishedName))
                output.DistinguishedName = searchResult.Attributes[LdapAttribute.DistinguishedName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.SAMAccountName))
                output.SamAccountName = searchResult.Attributes[LdapAttribute.SAMAccountName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenCreated))
                output.Created = searchResult.Attributes[LdapAttribute.WhenCreated].ParseValue<DateTime>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenChanged))
                output.Modified = searchResult.Attributes[LdapAttribute.WhenChanged].ParseValue<DateTime>();

            try
            {
                if (searchResult.Attributes.Contains(LdapAttribute.Surname))
                    output.Surname = searchResult.Attributes[LdapAttribute.Surname].ParseValue<string>();
                else
                {
                    var lastBreak = output.DisplayName.LastIndexOf(" ");
                    var surname = output.DisplayName.Substring(lastBreak + 1, output.DisplayName.Length - (lastBreak + 1));
                    output.Surname = surname;
                }
            }
            catch { }

            try
            {
                if (searchResult.Attributes.Contains(LdapAttribute.FirstName))
                    output.Firstname = searchResult.Attributes[LdapAttribute.FirstName].ParseValue<string>();
                else
                {
                    var lastBreak = output.DisplayName.LastIndexOf(" ");
                    var firstname = output.DisplayName.Substring(0, lastBreak);
                    output.Firstname = firstname;
                }
            }
            catch { }

            if (searchResult.Attributes.Contains(LdapAttribute.SAMAccountName))
                output.SamAccountName = searchResult.Attributes[LdapAttribute.SAMAccountName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.UserAccountControl))
            {
                output.UserAccountControl = searchResult.Attributes[LdapAttribute.UserAccountControl].ParseValue<int>();
            }

            return output;
        }

        public static LdapGroup ToGroupResult(this SearchResultEntry searchResult)
        {
            if (searchResult == null || searchResult.Attributes.Count == 0)
                return default;

            LdapGroup output = new();

            if (searchResult.Attributes.Contains(LdapAttribute.DisplayName))
                output.DisplayName = searchResult.Attributes[LdapAttribute.DisplayName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectCategory))
                output.ObjectCategory = searchResult.Attributes[LdapAttribute.ObjectCategory].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.ObjectGUID))
                output.ObjectGUID = searchResult.Attributes[LdapAttribute.ObjectGUID].ParseValue<Guid>();

            if (searchResult.Attributes.Contains(LdapAttribute.Objectsid))
            {
#pragma warning disable CA1416 // Validate platform compatibility
                try
                {
                    var acc = searchResult.Attributes[LdapAttribute.Objectsid].ParseValue<SecurityIdentifier>();
                    output.ObjectSid = acc.AccountDomainSid.ToString().ToLower();
                }
                catch
                {
                    output.ObjectSid = null;
                }
#pragma warning restore CA1416 // Validate platform compatibility
            }

            if (searchResult.Attributes.Contains(LdapAttribute.Member))
            {
                var members = searchResult.Attributes[LdapAttribute.Member].ParseValues<string>();
                output.Members = members;
            }


            if (searchResult.Attributes.Contains(LdapAttribute.SAMAccountName))
                output.SamAccountName = searchResult.Attributes[LdapAttribute.SAMAccountName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.DistinguishedName))
                output.DistinguishedName = searchResult.Attributes[LdapAttribute.DistinguishedName].ParseValue<string>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenCreated))
                output.Created = searchResult.Attributes[LdapAttribute.WhenCreated].ParseValue<DateTime>();

            if (searchResult.Attributes.Contains(LdapAttribute.WhenChanged))
                output.Modified = searchResult.Attributes[LdapAttribute.WhenChanged].ParseValue<DateTime>();


            return output;
        }
    }
}

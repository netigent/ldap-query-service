namespace Netigent.Utils.Ldap.Constants
{
    public static class SupportedAttributes
    {
        public static readonly string[] User =
        [
            LdapAttribute.MemberOfDn,
            LdapAttribute.DisplayName,
            LdapAttribute.SAMAccountName,
            LdapAttribute.Mail,
            LdapAttribute.Objectsid,
            LdapAttribute.Department,
            LdapAttribute.ObjectCategory,
            LdapAttribute.ObjectGUID,
            LdapAttribute.UserPrincipalName,
            LdapAttribute.PreferredLanguage,
            LdapAttribute.DistinguishedName,
            LdapAttribute.WhenChanged,
            LdapAttribute.WhenCreated,
            LdapAttribute.FirstName,
            LdapAttribute.Surname,
            LdapAttribute.AzureObjectId,
            LdapAttribute.City,
            LdapAttribute.Company,
            LdapAttribute.Country,
            LdapAttribute.EmployeeID,
            LdapAttribute.JobTitle,
            LdapAttribute.LastLogon,
            LdapAttribute.LastLogonTimestamp,
            LdapAttribute.LockoutTime,
            LdapAttribute.LogonCount,
            LdapAttribute.ManagerDn,
            LdapAttribute.MobilePhone,
            LdapAttribute.OfficeName,
            LdapAttribute.OfficePhone,
            LdapAttribute.PwdLastSet,
            LdapAttribute.State,
            LdapAttribute.Street,
            LdapAttribute.ZipPostalCode,
            LdapAttribute.UserAccountControl,
            LdapAttribute.Description,
        ];

        public static readonly string[] Group =
        [
            LdapAttribute.DisplayName,
            LdapAttribute.SAMAccountName,
            LdapAttribute.Objectsid,
            LdapAttribute.ObjectCategory,
            LdapAttribute.ObjectGUID,
            LdapAttribute.Member,
            LdapAttribute.DistinguishedName,
            LdapAttribute.WhenChanged,
            LdapAttribute.WhenCreated,
            LdapAttribute.AzureObjectId,
        ];
    }
}

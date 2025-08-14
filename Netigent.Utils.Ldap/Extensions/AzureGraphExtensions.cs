using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace Netigent.Utils.Ldap.Extensions
{
    public static class AzureGraphExtensions
    {
        public static GraphUserUpsertRequest ToGraphRequest(this IList<DirectoryAttribute> directoryAttributes, string setPassword = "", bool? accountEnabled = false)
        {
            var user = new GraphUserUpsertRequest
            {
                ForceChangePasswordNextSignIn = true,
                AccountEnabled = accountEnabled,
                City = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.City)?[0]?.ToString(),
                Company = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Company)?[0]?.ToString(),
                Department = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Department)?[0]?.ToString(),
                Description = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Description)?[0]?.ToString(),
                DisplayName = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.DisplayName)?[0]?.ToString(),
                GivenName = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.FirstName)?[0]?.ToString(),
                InitialPassword = setPassword?.Length > 0 ? setPassword : null,
                JobTitle = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.JobTitle)?[0]?.ToString(),
                Mail = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Mail)?[0]?.ToString(),
                Mobile = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.MobilePhone)?[0]?.ToString(),
                ObjectId = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.AzureObjectId)?[0]?.ToString(),
                Office = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.OfficeName)?[0]?.ToString(),
                PostalCode = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.ZipPostalCode)?[0]?.ToString(),
                Street = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Street)?[0]?.ToString(),
                Surname = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.Surname)?[0]?.ToString(),
                UserPrincipalName = directoryAttributes.FirstOrDefault(a => a.Name == LdapAttribute.UserPrincipalName)?[0]?.ToString(),
            };

            return user;
        }
    }
}

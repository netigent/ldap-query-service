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

        public string ObjectCategory { get; set; }
        public Guid ObjectGUID { get; set; }
        public string UserPrincipalName { get; set; }
        public string PreferredLanguage { get; set; }
        public string Firstname { get; set; }
        public string Surname { get; set; }
        public string DistinguishedName { get; set; }

        /// <summary>
        /// Azure ObjectGUID (msDS-aadObjectId)
        /// </summary>
        public Guid AzureObjectId { get; set; }

        //Login Related
        public DateTime? LastLogon { get; set; }
        public int LockoutTime { get; set; } = 0;
        public string PwdLastSet { get; set; }
        public int LogonCount { get; set; } = 0;
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }

        //Job Related
        public string ManagerCn { get; set; }
        public string Company { get; set; }
        public string EmployeeID { get; set; }
        public string JobTitle { get; set; }
        public string Department { get; set; }

        //Address Information
        public string Country { get; set; }
        public string City { get; set; }
        public string MobilePhone { get; set; }
        public string OfficeName { get; set; }
        public string OfficePhone { get; set; }
        public string ZipPostalCode { get; set; }
        public string State { get; set; }
        public string Street { get; set; }

        //User Account Control
        public int? UserAccountControl { get; set; }
    }
}
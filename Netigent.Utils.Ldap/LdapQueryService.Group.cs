using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace Netigent.Utils.Ldap
{
    public partial class LdapQueryService
    {
        /// <inheritdoc />
        public IList<LdapGroup>? GetGroups()
        {
            if (!_hasServiceAccount)
            {
                return null;
            }

            IList<LdapGroup> results = new List<LdapGroup>();

            foreach (SearchResultEntry r in SearchLdap(string.Format(LdapFilter.AllGroups), AttributeList.Group))
                results.Add(r.ToGroupResult());

            return results;
        }

        /// <inheritdoc />
        public LdapGroup? GetGroup(LdapQueryAttribute groupQueryType, string groupString)
        {
            if (!_hasServiceAccount)
            {
                return null;
            }

            var groupQueryString = string.Empty;
            switch (groupQueryType)
            {
                case LdapQueryAttribute.sAMAccountName:
                    groupQueryString = string.Format(LdapFilter.FindGroupBySam, groupString);
                    break;
                case LdapQueryAttribute.distinguishedName:
                    groupQueryString = string.Format(LdapFilter.FindGroupByDn, groupString);
                    break;
                case LdapQueryAttribute.objectGUID:
                    groupQueryString = string.Format(LdapFilter.FindGroupByGuid, groupString);
                    break;
                case LdapQueryAttribute.displayName:
                    groupQueryString = string.Format(LdapFilter.FindGroupByDisplayname, groupString);
                    break;
                default:
                    return default;
            }

            var result = SearchLdap(groupQueryString, AttributeList.Group);
            if (result.Count > 0)
                return result[0].ToGroupResult();

            return default;
        }

        /// <inheritdoc />
        public bool MemberOf(LdapQueryAttribute userQueryType, string userString, LdapQueryAttribute groupQueryType, string groupString)
        {
            if (!_hasServiceAccount)
            {
                return false;
            }

            var ldapUser = GetUser(userQueryType, userString);
            if (ldapUser == null || ldapUser == default || ldapUser?.MemberOf?.Count == 0)
                return false;

            var ldapGroup = GetGroup(groupQueryType, groupString);
            if (ldapGroup == null || ldapGroup == default || string.IsNullOrEmpty(ldapGroup?.DistinguishedName))
                return false;

            return ldapUser.MemberOf.Contains(ldapGroup.DistinguishedName);
        }
    }
}

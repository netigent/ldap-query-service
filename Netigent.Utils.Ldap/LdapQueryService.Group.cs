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

            foreach (SearchResultEntry r in SearchLdap(string.Format(LdapFilter.AllGroups), SupportedAttributes.Group))
                results.Add(r.ToGroupResult());

            return results;
        }

        /// <inheritdoc />
        public LdapGroup? GetGroup(string groupName, LdapQueryAttribute groupQueryType = LdapQueryAttribute.DisplayName)
        {
            if (!_hasServiceAccount)
            {
                return null;
            }

            var groupQueryString = string.Empty;
            switch (groupQueryType)
            {
                case LdapQueryAttribute.SamAccountName:
                    groupQueryString = string.Format(LdapFilter.FindGroupBySam, groupName);
                    break;
                case LdapQueryAttribute.Dn:
                    groupQueryString = string.Format(LdapFilter.FindGroupByDn, groupName);
                    break;
                case LdapQueryAttribute.ObjectId:
                    groupQueryString = string.Format(LdapFilter.FindGroupByGuid, groupName);
                    break;
                case LdapQueryAttribute.DisplayName:
                    groupQueryString = string.Format(LdapFilter.FindGroupByDisplayname, groupName);
                    break;
                default:
                    return default;
            }

            var result = SearchLdap(groupQueryString, SupportedAttributes.Group);
            if (result.Count > 0)
                return result[0].ToGroupResult();

            return default;
        }

        /// <inheritdoc />
        public bool MemberOf(string username, string groupName, LdapQueryAttribute groupQueryType = LdapQueryAttribute.DisplayName)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null || userResult.Data.MemberOf?.Count == 0)
            {
                return false;
            }

            var ldapGroup = GetGroup(groupName, groupQueryType);
            if (ldapGroup == null || ldapGroup == default || string.IsNullOrEmpty(ldapGroup?.DistinguishedName))
                return false;

            return userResult.Data.MemberOf.Contains(ldapGroup.DistinguishedName);
        }
    }
}

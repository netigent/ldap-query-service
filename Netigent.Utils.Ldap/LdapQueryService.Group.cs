using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
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
        public bool IsMemberOf(string username, string groupName, LdapQueryAttribute groupQueryType = LdapQueryAttribute.DisplayName)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null || !(userResult.Data.MemberOf?.Count > 0))
            {
                return false;
            }

            var ldapGroup = GetGroup(groupName, groupQueryType);
            if (ldapGroup == null || ldapGroup == default || string.IsNullOrEmpty(ldapGroup?.DistinguishedName))
                return false;

            return userResult.Data.MemberOf.Contains(ldapGroup.DistinguishedName);
        }

        public LdapResult AddToGroup(string username, string groupDn)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return new LdapResult { Message = userResult.Message };
            }

            try
            {
                const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
                using (var group = new DirectoryEntry(
                    $"LDAP://{_config.FullDNS}/{groupDn}",
                    $"{_config.UserLoginDomain}\\{_config.ServiceAccount}",
                    _config.ServiceKey,
                    authenticationTypes))
                {
                    group.Properties[LdapAttribute.Member].Add(userResult.Data.DistinguishedName);
                    group.CommitChanges();
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Added to {groupDn}"
                };
            }
            catch (Exception ex)
            {

                return new LdapResult
                {
                    Success = true,
                    Message = $"Failed: Added to {groupDn} - {ex.Message}"
                };
            }
        }

        public LdapResult RemoveGroup(string username, string groupDn)
        {
            // Get User.
            LdapResult<LdapUser> userResult = FindUser(username);
            if (!userResult.Success || userResult.Data == null)
            {
                return new LdapResult { Message = userResult.Message };
            }

            try
            {
                const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
                using (var group = new DirectoryEntry(
                    $"{_fullLdapPath}/{groupDn}",
                    $"{_config.UserLoginDomain}\\{GetPlainUsername(_config.ServiceAccount)}",
                    _config.ServiceKey,
                    authenticationTypes))
                {
                    group.Properties[LdapAttribute.Member].Remove(userResult.Data.DistinguishedName);
                    group.CommitChanges();
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Removed from {groupDn}"
                };
            }
            catch (Exception ex)
            {
                return new LdapResult
                {
                    Success = true,
                    Message = $"Failed: Removing from {groupDn} - {ex.Message}"
                };
            }
        }
    }
}

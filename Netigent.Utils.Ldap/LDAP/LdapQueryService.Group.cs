using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;

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
        public bool IsMemberOf(string username, string groupname)
        {
            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null || !(foundUserResult.Data.MemberOf?.Count > 0))
                return false;


            LdapResult<LdapGroup> foundGroupResult = GetGroup(groupname);
            if (!foundGroupResult.Success || foundGroupResult.Data == null)
                return false;

            return foundUserResult.Data.MemberOf.Contains(foundGroupResult.Data.DistinguishedName);
        }

        /// <inheritdoc />
        public async Task<LdapResult> AddToGroupAsync(string username, string group)
        {

            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return new LdapResult { Message = foundUserResult.Message };
            }

            LdapResult<LdapGroup> foundGroupResult = GetGroup(group);
            if (!foundGroupResult.Success || foundGroupResult.Data == null)
            {
                return new LdapResult { Message = foundGroupResult.Message };
            }

            try
            {
                const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
                using (var groupDE = new DirectoryEntry(
                    $"LDAP://{_config.FullDNS}/{foundGroupResult.Data.DistinguishedName}",
                    $"{_config.UserLoginDomain}\\{_config.ServiceAccount.GetPlainUsername()}",
                    _config.ServiceKey,
                    authenticationTypes))
                {
                    groupDE.Properties[LdapAttribute.Member].Add(foundUserResult.Data.DistinguishedName);
                    groupDE.CommitChanges();
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Added to {foundGroupResult.Data.DistinguishedName} {foundGroupResult.Data.ObjectGUID}"
                };
            }
            catch (Exception ex)
            {
                // Try Azure if cant connect
                if (ex.Message.Contains(LdapWarnings.ServerNotOpertational) && _hasAzureGraph)
                {
                    var graphResult = await _azureGraph.AddMemberAsync(
                        userId: foundUserResult.Data.AzureOrObjectID,
                        groupId: foundGroupResult.Data.AzureOrObjectID);

                    return graphResult;
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Failed: Added to {foundGroupResult.Data.DistinguishedName} {foundGroupResult.Data.ObjectGUID} - {ex.Message}"
                };
            }
        }

        /// <inheritdoc />
        public async Task<LdapResult> RemoveGroupAsync(string username, string group)
        {
            // Get User.
            LdapResult<LdapUser> foundUserResult = GetUser(username);
            if (!foundUserResult.Success || foundUserResult.Data == null)
            {
                return new LdapResult { Message = foundUserResult.Message };
            }

            LdapResult<LdapGroup> foundGroupResult = GetGroup(group);
            if (!foundGroupResult.Success || foundGroupResult.Data == null)
            {
                return new LdapResult { Message = foundGroupResult.Message };
            }

            try
            {
                const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;
                using (var groupDE = new DirectoryEntry(
                    $"{_fullLdapPath}/{foundGroupResult.Data.DistinguishedName}",
                    $"{_config.UserLoginDomain}\\{_config.ServiceAccount.GetPlainUsername()}",
                    _config.ServiceKey,
                    authenticationTypes))
                {
                    groupDE.Properties[LdapAttribute.Member].Remove(foundUserResult.Data.DistinguishedName);
                    groupDE.CommitChanges();
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Removed from {foundGroupResult.Data.DistinguishedName} {foundGroupResult.Data.ObjectGUID}"
                };
            }
            catch (Exception ex)
            {
                // Try Azure if cant connect
                if (ex.Message.Contains(LdapWarnings.ServerNotOpertational) && _hasAzureGraph)
                {
                    var graphResult = await _azureGraph.RemoveMemberAsync(
                        userId: foundUserResult.Data.AzureOrObjectID,
                        groupId: foundGroupResult.Data.AzureOrObjectID);

                    return graphResult;
                }

                return new LdapResult
                {
                    Success = true,
                    Message = $"Failed: Removing from {foundGroupResult.Data.DistinguishedName} {foundGroupResult.Data.ObjectGUID} - {ex.Message}"
                };
            }
        }

        /// <inheritdoc />
        public LdapResult<LdapGroup> GetGroup(string groupname)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult<LdapGroup>
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (string.IsNullOrEmpty(groupname))
            {
                return new LdapResult<LdapGroup>
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Lets figure the username
            LdapGroup? group = null;

            // Attempt Search by Object
            if (group == null && Guid.TryParse(groupname, out Guid groupId) == true)
            {
                return GetGroup(groupId);
            }

            // Distingused Name Search
            if (groupname.Contains("DC="))
            {
                // LDAP Search
                var result = SearchLdap(string.Format(LdapFilter.FindGroupByDn, groupname), SupportedAttributes.Group);

                if (result.Count > 0)
                    group = result[0].ToGroupResult();
            }

            // Attempt to find by SAM
            if (group == null)
            {
                // LDAP Search
                var result = SearchLdap(string.Format(LdapFilter.FindGroupBySam, groupname), SupportedAttributes.Group);

                if (result.Count > 0)
                    group = result[0].ToGroupResult();
            }

            if (group == null)
            {
                // LDAP Search
                var result = SearchLdap(string.Format(LdapFilter.FindGroupByDisplayname, groupname), SupportedAttributes.Group);

                if (result.Count > 0)
                    group = result[0].ToGroupResult();
            }

            if (group != null)
            {
                return new LdapResult<LdapGroup>
                {
                    Success = true,
                    Data = group,
                    Message = "Found Group",
                };
            }

            return new LdapResult<LdapGroup>
            {
                Message = $"Couldnt find '{groupname}', checked Guid, Dn, SAM and DisplayName."
            };
        }

        /// <inheritdoc />
        public LdapResult<LdapGroup> GetGroup(Guid groupId)
        {
            if (!_hasServiceAccount)
            {
                return new LdapResult<LdapGroup>
                {
                    Success = false,
                    Message = "ServiceAccount, Not Configured",
                };
            }

            if (groupId == default)
            {
                return new LdapResult<LdapGroup>
                {
                    Success = false,
                    Message = "Missing Arguments",
                };
            }

            // Lets figure the username
            LdapGroup? group = null;
            var result = SearchLdap(string.Format(LdapFilter.FindGroupByAzureIdOrObjectId, groupId.ToString(), groupId.ToBinaryString()), SupportedAttributes.Group);

            if (result.Count > 0)
                group = result[0].ToGroupResult();


            if (group != null)
            {
                return new LdapResult<LdapGroup>
                {
                    Success = true,
                    Data = group,
                    Message = "Found Group",
                };
            }

            return new LdapResult<LdapGroup>
            {
                Message = $"Couldnt find '{groupId.ToString()}', checked AzureId and ObjectId."
            };
        }
    }
}

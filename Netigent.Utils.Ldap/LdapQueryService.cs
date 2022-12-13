using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;

namespace Netigent.Utils.Ldap
{
    public class LdapQueryService : ILdapQueryService, IDisposable
    {
        private readonly string[] userFilters = new[] {
            Constants.memberOf,
            Constants.displayName,
            Constants.sAMAccountName,
            Constants.mail,
            Constants.objectsid,
            Constants.department,
            Constants.objectCategory,
            Constants.objectGUID,
            Constants.userPrincipalName,
            Constants.preferredLanguage,
            Constants.distinguishedName,
            Constants.whenChanged,
            Constants.whenCreated,
            Constants.givenName,
            Constants.sn,
            Constants.AzureObjectId,

            Constants.City,
            Constants.Company,
            Constants.Country,
            Constants.EmployeeID,
            Constants.JobTitle,
            Constants.LastLogon,
            Constants.LastLogonTimestamp,
            Constants.LockoutTime,
            Constants.LogonCount,
            Constants.ManagerCn,
            Constants.MobilePhone,
            Constants.OfficeName,
            Constants.OfficePhone,
            Constants.PwdLastSet,
            Constants.State,
            Constants.Street,
            Constants.ZipPostalCode
            };

        private readonly string[] groupFilters = new[] {
            Constants.displayName,
            Constants.sAMAccountName,
            Constants.objectsid,
            Constants.objectCategory,
            Constants.objectGUID,
            Constants.member,
            Constants.distinguishedName,
            Constants.whenChanged,
            Constants.whenCreated
            };

        private readonly LdapConfig _config;
        private readonly LdapConnection _connection;

        /// <summary>
        /// Has the User Logged In.
        /// </summary>
        public bool LoggedIn { get; internal set; } = false;

        /// <summary>
        /// The Logged In User Object.
        /// </summary>
        public LdapUser User { get; internal set; }

        /// <summary>
        /// Construct LdapQueryService using parameters.
        /// </summary>
        /// <param name="config"></param>
        public LdapQueryService(IOptions<LdapConfig> config)
        {
            _config = config.Value;

            Debug.WriteLine($"Ldap Authentication: Connecting to {_config.FullDNS}:{_config.Port} SSL={_config.UseSSL.ToString()}");
            _connection = new LdapConnection($"{_config.FullDNS}:{_config.Port}");

            _connection.SessionOptions.SecureSocketLayer = _config.UseSSL;
            _connection.SessionOptions.ProtocolVersion = 3;
            _connection.AuthType = AuthType.Basic;

            if (!string.IsNullOrEmpty(_config.UserLoginDomain))
                Debug.WriteLine($"Ldap Authentication: Default UserLoginDomain={_config.UserLoginDomain} Enabled");
        }

        /// <summary>
        /// Construct LdapQueryService using parameters.
        /// </summary>
        /// <param name="serverDns">FullDNS for Domain e.g. myorg.com Or DC1.myorg.com</param>
        /// <param name="searchBase">Root to Search from e.g. OU=AADDC Users,DC=myorg,DC=com</param>
        /// <param name="port">Default LDAP Port 636 used</param>
        /// <param name="useSSL">Connect with SSL</param>
        /// <param name="defaultUserDomain">(Optional) If a value e.g. myorg is supplied then, Login will ignore supplied  </param>
        public LdapQueryService(string serverDns, string searchBase, int port = 636, bool useSSL = false, string defaultUserDomain = "")
        {
            _config = new LdapConfig
            {
                FullDNS = serverDns,
                Port = port,
                UseSSL = useSSL,
                SearchBase = searchBase,
                UserLoginDomain = defaultUserDomain
            };

            Debug.WriteLine($"Ldap Authentication: Connecting to {_config.FullDNS}:{_config.Port} SSL={_config.UseSSL.ToString()}");
            _connection = new LdapConnection($"{_config.FullDNS}:{_config.Port}");

            _connection.SessionOptions.SecureSocketLayer = _config.UseSSL;
            _connection.SessionOptions.ProtocolVersion = 3;
            _connection.AuthType = AuthType.Basic;

            if (!string.IsNullOrEmpty(_config.UserLoginDomain))
                Debug.WriteLine($"Ldap Authentication: Default UserLoginDomain={_config.UserLoginDomain} Enabled");
        }

        /// <summary>
        /// Attempt to Login, WARNING: Default domain must be set in the constructor!
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="errorMessage"></param>
        /// <returns></returns>
        public bool Login(string username, string password, out string errorMessage)
        {
            if (string.IsNullOrEmpty(_config.UserLoginDomain))
            {
                errorMessage = "No Default Domain Supplied";
                return false;
            }

            return Login(_config.UserLoginDomain, username, password, out errorMessage);
        }

        /// <summary>
        /// Attempt to Login, WARNING: If default domain was supplied in the constructor, domain will be ignored!
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="errorMessage"></param>
        /// <returns></returns>
        public bool Login(string domain, string username, string password, out string errorMessage, string serviceAccount = "", string serviceKey = "")
        {
            LoggedIn = false;
            errorMessage = string.Empty;

            try
            {
                // This could be a failed callback
                if (!string.IsNullOrEmpty(serviceAccount) && !string.IsNullOrEmpty(serviceKey) && username.Contains("@", StringComparison.InvariantCultureIgnoreCase))
                {
                    _connection.Bind(new NetworkCredential(serviceAccount, serviceKey));
                    username = GetUser(LdapQueryAttribute.mail, username)?.SamAccountName;
                }
                else if(username.Contains('\\') || username.Contains("@", StringComparison.InvariantCultureIgnoreCase))
                {
                    username = username.Contains("@", StringComparison.InvariantCultureIgnoreCase) ? username.Split('@')[0] : username.Split('\\')[1];
                }

                //Try connecting as username + password
                string userDomain = !string.IsNullOrEmpty(_config.UserLoginDomain) ? _config.UserLoginDomain : domain;
                Debug.WriteLine($"Ldap Authentication: Binding as {userDomain}\\{username}");
                _connection.Bind(new NetworkCredential(username, password, userDomain));

                User = GetUser(LdapQueryAttribute.sAMAccountName, username);
                LoggedIn = true;
            }
            catch (ObjectDisposedException ode)
            {
                errorMessage = $"ObjectDisposedException: {ode.Message} ( {ode.InnerException?.Message} )";
                Debug.WriteLine($"Ldap Authentication: ObjectDisposedException {ode.Message} ( {ode.InnerException?.Message} ), Stack: {ode.StackTrace}");
            }
            catch (LdapException le)
            {
                errorMessage = $"{le.Message}";
                Debug.WriteLine($"Ldap Authentication: LdapException {le.Message} ( {le.InnerException?.Message} ), Stack: {le.StackTrace}");
            }
            catch (InvalidOperationException ioe)
            {
                errorMessage = $"InvalidOperationException: {ioe.Message} ( {ioe.InnerException?.Message} )";
                Debug.WriteLine($"Ldap Authentication: InvalidOperationException {ioe.Message} ( {ioe.InnerException?.Message} ), Stack: {ioe.StackTrace}");
            }

            return LoggedIn;
        }

        public void Dispose()
        {
            try
            {
                Debug.WriteLine($"Ldap Authentication: Closing connection...");
                _connection.Dispose();
            }
            catch
            {

            }
        }

        public List<LdapUser> GetUsers()
        {
            List<LdapUser> results = new();

            foreach (SearchResultEntry r in ExecuteLdapQuery(string.Format(Constants.filterAllUsers), userFilters))
                results.Add(r.ToUserResult());

            return results;
        }

        public LdapUser GetUser() => User;

        public LdapUser GetUser(LdapQueryAttribute userQueryType, string userString)
        {
            var userQueryString = string.Empty;
            switch (userQueryType)
            {
                case LdapQueryAttribute.sAMAccountName:
                    userQueryString = string.Format(Constants.filterFindUserBySam, userString);
                    break;
                case LdapQueryAttribute.distinguishedName:
                    userQueryString = string.Format(Constants.filterFindUserByDn, userString);
                    break;
                case LdapQueryAttribute.objectGUID:
                    userQueryString = string.Format(Constants.filterFindUserByGuid, userString);
                    break;
                case LdapQueryAttribute.displayName:
                    userQueryString = string.Format(Constants.filterFindUserByDisplayname, userString);
                    break;
                case LdapQueryAttribute.mail:
                    userQueryString = string.Format(Constants.filterFindUserByEmail, userString);
                    break;
                default:
                    return default;
            }

            var result = ExecuteLdapQuery(userQueryString, userFilters);
            if (result.Count > 0)
                return result[0].ToUserResult();

            return default;
        }

        public List<LdapGroup> GetGroups()
        {
            List<LdapGroup> results = new();

            foreach (SearchResultEntry r in ExecuteLdapQuery(string.Format(Constants.filterAllGroups), groupFilters))
                results.Add(r.ToGroupResult());

            return results;
        }

        public LdapGroup GetGroup(LdapQueryAttribute groupQueryType, string groupString)
        {
            var groupQueryString = string.Empty;
            switch (groupQueryType)
            {
                case LdapQueryAttribute.sAMAccountName:
                    groupQueryString = string.Format(Constants.filterFindGroupBySam, groupString);
                    break;
                case LdapQueryAttribute.distinguishedName:
                    groupQueryString = string.Format(Constants.filterFindGroupByDn, groupString);
                    break;
                case LdapQueryAttribute.objectGUID:
                    groupQueryString = string.Format(Constants.filterFindGroupByGuid, groupString);
                    break;
                case LdapQueryAttribute.displayName:
                    groupQueryString = string.Format(Constants.filterFindGroupByDisplayname, groupString);
                    break;
                default:
                    return default;
            }

            var result = ExecuteLdapQuery(groupQueryString, groupFilters);
            if (result.Count > 0)
                return result[0].ToGroupResult();

            return default;
        }

        public bool MemberOf(LdapQueryAttribute groupQueryType, string groupString)
        {
            var ldapUser = GetUser();
            if (ldapUser == null || ldapUser == default || ldapUser?.MemberOf?.Count == 0)
                return false;

            var ldapGroup = GetGroup(groupQueryType, groupString);
            if (ldapGroup == null || ldapGroup == default || string.IsNullOrEmpty(ldapGroup?.DistinguishedName))
                return false;

            return ldapUser.MemberOf.Contains(ldapGroup.DistinguishedName);
        }

        public bool MemberOf(LdapQueryAttribute userQueryType, string userString, LdapQueryAttribute groupQueryType, string groupString)
        {
            var ldapUser = GetUser(userQueryType, userString);
            if (ldapUser == null || ldapUser == default || ldapUser?.MemberOf?.Count == 0)
                return false;

            var ldapGroup = GetGroup(groupQueryType, groupString);
            if (ldapGroup == null || ldapGroup == default || string.IsNullOrEmpty(ldapGroup?.DistinguishedName))
                return false;

            return ldapUser.MemberOf.Contains(ldapGroup.DistinguishedName);
        }

        SearchResultEntryCollection ExecuteLdapQuery(string ldapQuery, string[] filters)
        {
            SearchRequest r = new SearchRequest(
                    _config.SearchBase,
                    ldapQuery,
                    SearchScope.Subtree,
                    filters
            );

            Debug.WriteLine($"Sending Request: '{ldapQuery}', SearchBase='{_config.SearchBase}'");
            var sr = (SearchResponse)_connection.SendRequest(r);

            Debug.WriteLine($"Result Count = {sr.Entries.Count}");
            return sr.Entries;
        }

        public List<LdapGeneric> RunQuery(string filter)
        {
            List<LdapGeneric> results = new();

            foreach (SearchResultEntry r in ExecuteLdapQuery(filter, new[] { "*" }))
                results.Add(r.ToGenericResult());

            return results;
        }

    }
}

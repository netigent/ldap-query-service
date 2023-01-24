using Microsoft.Extensions.Options;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading.Tasks;

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
        /// <param name="maxTries">(Optional) Max Tries if LDAP is unavailable.</param>
        /// <param name="retryDelayMs">(Optional) Delay between Retry in MS</param>
        public LdapQueryService(string serverDns, string searchBase, int port = 636, bool useSSL = false, string defaultUserDomain = "", int maxTries = 1, int retryDelayMs = 300)
        {
            _config = new LdapConfig
            {
                FullDNS = serverDns,
                Port = port,
                UseSSL = useSSL,
                SearchBase = searchBase,
                UserLoginDomain = defaultUserDomain,
                MaxTries = maxTries,
                RetryDelayMs = retryDelayMs,
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
        public async Task<LoginResult> Login(string username, string password)
        {
            if (string.IsNullOrEmpty(_config.UserLoginDomain))
            {
                LoginResult loginResult = new LoginResult { ErrorMessage = "No Default Domain Supplied" };
                return loginResult;
            }

            return await Login(_config.UserLoginDomain, username, password);
        }

        /// <summary>
        /// Attempt to Login, WARNING: If default domain was supplied in the constructor, domain will be ignored!
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="errorMessage"></param>
        /// <returns></returns>
        public async Task<LoginResult> Login(string domain, string username, string password, string serviceAccount = "", string serviceKey = "")
        {
            LoginResult loginResult = new LoginResult();
            LoggedIn = false;

            int maxTries = _config.MaxTries > 0 ? _config.MaxTries : 1;
            int retryDelay = _config.RetryDelayMs >= 0 ? _config.RetryDelayMs : 300;
            string sAMAccountName = string.Empty;

            try
            {
                Exception lastException = null;

                for (int attempts = 0; attempts < maxTries; attempts++)
                {
                    try
                    {
                        // This could be a failed callback
                        if (!string.IsNullOrEmpty(serviceAccount) && !string.IsNullOrEmpty(serviceKey) && username.Contains("@"))
                        {
                            _connection.Bind(new NetworkCredential(serviceAccount, serviceKey));
                            sAMAccountName = GetUser(LdapQueryAttribute.mail, username)?.SamAccountName;

                            if (string.IsNullOrEmpty(sAMAccountName))
                            {
                                throw new Exception($"NoAccount: Couldnt an account using email '{username}'");
                            }
                        }
                        else if (username.Contains("\\") || username.Contains("@"))
                        {
                            sAMAccountName = username.Contains("@") ? username.Split('@')[0] : username.Split('\\')[1];
                        }

                        //Try connecting as username + password
                        string userDomain = !string.IsNullOrEmpty(_config.UserLoginDomain) ? _config.UserLoginDomain : domain;

                        Debug.WriteLine($"Ldap Authentication: Binding as {userDomain}\\{sAMAccountName}");

                        _connection.Bind(new NetworkCredential(sAMAccountName, password, userDomain));
                        User = GetUser(LdapQueryAttribute.sAMAccountName, sAMAccountName);

                        LoggedIn = true;
                    }
                    catch (Exception exception)
                    {
                        // LDAP unavailable and no retry remaining.
                        if (exception.IsLdapServerUnavailable() && attempts < (maxTries - 1))
                        {
                            // Also check if should build in time delay
                            if (retryDelay > 0)
                            {
                                await Task.Delay(retryDelay);
                            }
                        }
                        else
                        {
                            // Only return for server unavailable exceptions
                            lastException = exception;
                            break;
                        }
                    }
                }

                if (lastException != null)
                {
                    // Ran out of allowed attempts so throw last exception to allow containing code to deal with it.
                    throw lastException;
                }
            }
            catch (ObjectDisposedException ode)
            {
                loginResult.ErrorMessage = $"ObjectDisposedException: {ode.Message} ( {ode.InnerException?.Message} )";
                Debug.WriteLine($"Ldap Authentication: ObjectDisposedException {ode.Message} ( {ode.InnerException?.Message} ), Stack: {ode.StackTrace}");
            }
            catch (LdapException le)
            {
                loginResult.ErrorMessage = $"{le.Message}";
                Debug.WriteLine($"Ldap Authentication: LdapException {le.Message} ( {le.InnerException?.Message} ), Stack: {le.StackTrace}");
            }
            catch (InvalidOperationException ioe)
            {
                loginResult.ErrorMessage = $"InvalidOperationException: {ioe.Message} ( {ioe.InnerException?.Message} )";
                Debug.WriteLine($"Ldap Authentication: InvalidOperationException {ioe.Message} ( {ioe.InnerException?.Message} ), Stack: {ioe.StackTrace}");
            }
            catch (Exception ex)
            {
                loginResult.ErrorMessage = $"Exception: {ex.Message} ( {ex.InnerException?.Message} )";
                Debug.WriteLine($"Ldap Authentication: InvalidOperationException {ex.Message} ( {ex.InnerException?.Message} ), Stack: {ex.StackTrace}");
            }

            loginResult.Result = LoggedIn;
            return loginResult;
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
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
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

        public bool ResetUserLDAPPassword(string serviceAccount, string serviceKey, string container,
            string domainController, string userName, string newPassword, out bool unmetRequirements)
        {
            unmetRequirements = false;
            const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure |
                AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;

            DirectoryEntry searchRoot = null;
            DirectorySearcher searcher = null;
            DirectoryEntry userEntry = null;

            try
            {
                searchRoot = new DirectoryEntry(string.Format("LDAP://{0}/{1}",
                    domainController, container),
                    serviceAccount, serviceKey, authenticationTypes);

                searcher = new DirectorySearcher(searchRoot);
                searcher.Filter = string.Format(Constants.filterFindUserByDn, userName);
                searcher.SearchScope = System.DirectoryServices.SearchScope.Subtree;
                searcher.CacheResults = false;

                SearchResult searchResult = searcher.FindOne();
                if (searchResult == null)
                {
                    return false;
                }

                userEntry = searchResult.GetDirectoryEntry();

                userEntry.Invoke("SetPassword", new object[] { newPassword });
                userEntry.CommitChanges();

                return true;
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("800708C5"))
                {
                    unmetRequirements = true;
                }
                else
                {
                    throw ex;
                }
            }
            finally
            {
                if (userEntry != null) userEntry.Dispose();
                if (searcher != null) searcher.Dispose();
                if (searchRoot != null) searchRoot.Dispose();
            }

            return false;
        }
    }
}

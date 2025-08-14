using Microsoft.Extensions.Options;
using Netigent.Utils.Ldap.AzureAD;
using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap
{
    public partial class LdapQueryService : ILdapQueryService, IDisposable
    {
        #region ctor
        private readonly LdapConfig _config;
        private readonly LdapConnection _connection;
        private readonly NetworkCredential? _serviceAccount;
        private readonly bool _hasServiceAccount;

        private readonly string _fullLdapPath;

        private readonly GraphService _azureGraph;
        private readonly bool _hasAzureGraph;

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
        public LdapQueryService(string serverDns, string searchBase, int port = 636, bool useSSL = false, string defaultUserDomain = "", string serviceAccount = "", string serviceKey = "", int maxTries = 1, int retryDelayMs = 300)
        : this(new LdapConfig
        {
            FullDNS = serverDns,
            Port = port,
            UseSSL = useSSL,
            SearchBase = searchBase,
            UserLoginDomain = defaultUserDomain,
            MaxTries = maxTries,
            RetryDelayMs = retryDelayMs,
            ServiceAccount = serviceAccount,
            ServiceKey = serviceKey,
        })
        {
        }

        /// <summary>
        /// Construct LdapQueryService using parameters, usefull for DI.
        /// </summary>
        /// <param name="config"></param>
        public LdapQueryService(IOptions<LdapConfig> config) :
            this(config.Value)
        {
        }

        /// <summary>
        /// Construct LdapQueryService using parameters.
        /// </summary>
        /// <param name="config"></param>
        public LdapQueryService(LdapConfig config)
        {
            _config = config;
            _connection = BuildConnection();

            // Old Format LDAP
            _fullLdapPath = $"{(_config.UseSSL ? "LDAPS" : "LDAP")}://{_config.FullDNS}{(_config.Port != 389 ? $":{_config.Port}" : string.Empty)}";

            if (string.IsNullOrEmpty(_config.UserLoginDomain))
            {
                throw new Exception($"{nameof(LdapQueryService)} - No 'UserLoginDomain' configured");
            }

            Debug.WriteLine($"{nameof(LdapQueryService)} - Default 'UserLoginDomain' = '{_config.UserLoginDomain}'");
            Debug.WriteLine($"{nameof(LdapQueryService)} - Connection {_config.FullDNS}:{_config.Port} SSL={_config.UseSSL.ToString()}");

            // Initialize Service Account
            if (config.ServiceAccount?.Length > 0 && config.ServiceKey?.Length > 0)
            {
                _serviceAccount = new NetworkCredential(
                    userName: config.ServiceAccount.GetPlainUsername(),
                    password: config.ServiceKey,
                    domain: config.UserLoginDomain);

                // Attempt to bindService Account
                var bindResult = BindConnection(_serviceAccount);

                if (!bindResult.Success)
                {
                    throw new Exception($"{nameof(LdapQueryService)} - Service Account '{config.ServiceAccount}' - Failed {bindResult.Message}");
                }

                // We have a service account
                _hasServiceAccount = bindResult.Success;
                Debug.WriteLine($"{nameof(LdapQueryService)} - Service Account '{config.ServiceAccount}' - Authenticated");
            }
            else
            {
                _hasServiceAccount = false;
            }

            if (config.AzureTenentId?.Length > 0 && config.AzureClientId?.Length > 0 && config.AzureClientSecret?.Length > 0)
            {
                _hasAzureGraph = true;
                _azureGraph = new GraphService(
                    tenantId: config.AzureTenentId,
                    clientId: config.AzureClientId,
                    clientSecret: config.AzureClientSecret);
            }
            else
            {
                _hasAzureGraph = false;
            }


        }
        #endregion

        /// <summary>
        /// Dispose.
        /// </summary>
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

        /// <inheritdoc />
        public IList<LdapGeneric> RunSearchQuery(string filter)
        {
            IList<LdapGeneric> results = new List<LdapGeneric>();

            foreach (SearchResultEntry r in SearchLdap(filter, new[] { "*" }))
                results.Add(r.ToGenericResult());

            return results;
        }

        #region Internal
        /// <summary>
        /// Attempt to Login, WARNING: Default domain must be set in the constructor!
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="errorMessage"></param>
        /// <returns></returns>
        private LdapResult BindConnection(NetworkCredential credentials, LdapConnection alternativeConnection = null)
        {
            Exception lastException = null;

            for (int i = 0; i < _config.MaxTries; i++)
            {
                try
                {
                    if (alternativeConnection != null)
                    {
                        alternativeConnection.Bind(credentials);
                        return new LdapResult { Success = true, Message = string.Empty };
                    }

                    _connection.Bind(credentials);
                    return new LdapResult { Success = true, Message = string.Empty };
                }
                catch (Exception exception)
                {
                    // LDAP unavailable and no retry remaining.
                    if (exception.IsLdapServerUnavailable() && i < _config.MaxTries)
                    {
                        Task.Delay(_config.RetryDelayMs > 0 ? _config.RetryDelayMs : 300);
                    }

                    // Only return for server unavailable exceptions
                    lastException = exception;
                    break;
                }
            }

            return new LdapResult
            {
                Success = false,
                Message = $"{lastException.Message}.{lastException?.InnerException?.Message ?? string.Empty}"
            };
        }

        /// <summary>
        /// Build LDAP Connection.
        /// </summary>
        /// <returns></returns>
        private LdapConnection BuildConnection()
        {
            var identifier = new LdapDirectoryIdentifier(_config.FullDNS, _config.Port, true, false);
            LdapConnection connection = new LdapConnection(identifier);
            connection.SessionOptions.SecureSocketLayer = _config.UseSSL;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
            connection.SessionOptions.VerifyServerCertificate += (conn, cert) => true;
            connection.AuthType = AuthType.Negotiate | AuthType.Basic;
            return connection;
        }

        /// <summary>
        /// Saves LDAP entry with failover to DirectoryEntry COM API for password changes.
        /// </summary>
        private LdapResult SaveLdap(string dn, LdapObjectType objectType, IList<DirectoryAttribute> directoryAttributes)
        {
            bool isExisting = objectType == LdapObjectType.Group
                ? (GetGroup(dn).Data?.DistinguishedName ?? string.Empty) == dn
                : (GetUser(dn).Data?.DistinguishedName ?? string.Empty) == dn;

            try
            {
                if (!isExisting)
                {
                    var addRequest = new AddRequest(dn, objectType == LdapObjectType.Group ? LdapObject.Group : LdapObject.User);

                    foreach (DirectoryAttribute attr in directoryAttributes)
                    {
                        if (!attr.Name.Equals(LdapAttribute.UserPassword, StringComparison.InvariantCultureIgnoreCase) && !attr.Name.Equals(LdapAttribute.UnicodePassword, StringComparison.InvariantCultureIgnoreCase))
                        {
                            addRequest.Attributes.Add(attr);
                        }
                    }

                    var addResponse = (AddResponse)_connection.SendRequest(addRequest);

                    return new LdapResult
                    {
                        Success = addResponse.ResultCode == ResultCode.Success,
                        Message = addResponse.ErrorMessage,
                    };
                }
                else
                {
                    var modifications = new List<DirectoryAttributeModification>();

                    foreach (DirectoryAttribute attr in directoryAttributes)
                    {
                        var updateAttribute = new DirectoryAttributeModification
                        {
                            Name = attr.Name,
                            Operation = DirectoryAttributeOperation.Replace
                        };

                        if (attr.Name.Equals(LdapAttribute.UnicodePassword, StringComparison.OrdinalIgnoreCase))
                        {
                            string password = attr[0].ToString();
                            byte[] pwdBytes = Encoding.Unicode.GetBytes($"\"{password}\"");
                            updateAttribute.Add(pwdBytes);
                        }
                        else
                        {
                            foreach (var val in attr)
                            {
                                if (val is byte[] bytes)
                                    updateAttribute.Add(bytes);
                                else if (val != null)
                                    updateAttribute.Add(val.ToString());
                            }
                        }
                        modifications.Add(updateAttribute);
                    }

                    var modResponse = _connection.SendRequest(new ModifyRequest(dn, modifications.ToArray()));
                    return new LdapResult
                    {
                        Success = modResponse.ResultCode == ResultCode.Success,
                        Message = modResponse.ErrorMessage,
                    };

                }
            }
            catch (DirectoryOperationException dex)
            {
                // Check if this is the WILL_NOT_PERFORM / insufficient permission case
                if (dex.Response?.ErrorMessage?.Contains("WILL_NOT_PERFORM") == true ||
                    dex.Response?.ErrorMessage?.Contains("INSUFF_ACCESS_RIGHTS") == true ||
                    dex.Response?.ResultCode == ResultCode.UnwillingToPerform ||
                    dex.Response?.ResultCode == ResultCode.InsufficientAccessRights)
                {
                    return new LdapResult
                    {
                        Success = false,
                        Message = $"{dex.Response?.ErrorMessage ?? string.Empty} - {LdapWarnings.AzureCloud}"
                    };
                }

                // Rethrow if not the known failover case
                throw;
            }
            catch (Exception ex)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        /// <summary>
        /// Searches for LDAP item.
        /// </summary>
        /// <param name="ldapQuery"></param>
        /// <param name="fetchAttributes"></param>
        /// <param name="alternativeConnection"></param>
        /// <returns></returns>
        private SearchResultEntryCollection SearchLdap(string ldapQuery, string[] fetchAttributes, LdapConnection? alternativeConnection = null)
        {
            SearchRequest r = new SearchRequest(
                    _config.SearchBase,
                    ldapQuery,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    fetchAttributes
            );

            Debug.WriteLine($"Sending Request: '{ldapQuery}', SearchBase='{_config.SearchBase}'");
            var sr = (SearchResponse)(alternativeConnection ?? _connection).SendRequest(r);

            Debug.WriteLine($"Result Count = {sr.Entries.Count}");
            return sr.Entries;
        }
        #endregion
    }
}

using Microsoft.Extensions.Options;
using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Extensions;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Linq;
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

            if (string.IsNullOrEmpty(_config.UserLoginDomain))
            {
                throw new Exception($"{nameof(LdapQueryService)} - No 'UserLoginDomain' configured");
            }

            Debug.WriteLine($"{nameof(LdapQueryService)} - Default 'UserLoginDomain' = '{_config.UserLoginDomain}'");
            Debug.WriteLine($"{nameof(LdapQueryService)} - Connection {_config.FullDNS}:{_config.Port} SSL={_config.UseSSL.ToString()}");

            // Initialize Service Account
            if (config.ServiceAccount?.Length > 0 && config.ServiceKey?.Length > 0)
            {
                if (!config.ServiceAccount.Contains("@") && !config.ServiceAccount.Contains("\\"))
                {
                    _serviceAccount = new NetworkCredential(
                        userName: $"{config.UserLoginDomain}\\{config.ServiceAccount}",
                        password: config.ServiceKey);
                }
                else
                {
                    _serviceAccount = new NetworkCredential(
                        userName: config.ServiceAccount,
                        password: config.ServiceKey);
                }

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
            LdapConnection connection = new LdapConnection($"{_config.FullDNS}:{_config.Port}");
            connection.SessionOptions.SecureSocketLayer = _config.UseSSL;
            connection.SessionOptions.ProtocolVersion = 3;
            connection.AuthType = AuthType.Basic;

            return connection;
        }

        /// <summary>
        /// Adds an LDAP entry.
        /// </summary>
        /// <param name="dn">cn=John Doe,ou=Users,dc=example,dc=com</param>
        /// <param name="objectClass">user or group</param>
        /// <param name="directoryAttributes"></param>
        /// <returns></returns>
        private LdapResult AddLdap(string dn, string objectClass, IList<DirectoryAttribute> directoryAttributes)
        {
            try
            {
                AddRequest addRequest = new AddRequest(dn, objectClass);

                // Set attributes for the new user
                foreach (DirectoryAttribute directoryAttribute in directoryAttributes)
                {
                    addRequest.Attributes.Add(directoryAttribute);
                }

                // Send the AddRequest to create the user
                DirectoryResponse addResponse = _connection.SendRequest(addRequest) as AddResponse;

                return new LdapResult
                {
                    Success = addResponse.ResultCode == ResultCode.Success,
                    Message = addResponse.ErrorMessage,
                };
            }
            catch (Exception ex)
            {
                return new LdapResult
                {
                    Success = false,
                    Message = ex.Message,
                };
            }
        }

        private LdapResult ModifyLdap(string dn, IList<DirectoryAttribute> directoryAttributes)
        {
            try
            {
                // Process each attribute
                foreach (var attr in directoryAttributes)
                {
                    // Special case: password changes
                    if (attr.Name.Equals(LdapAttribute.UnicodePassword, StringComparison.OrdinalIgnoreCase))
                    {
                        // AD expects password in UTF-16 with quotes
                        string password = attr[0].ToString();
                        byte[] pwdBytes = Encoding.Unicode.GetBytes($"\"{password}\"");

                        var pwdRequest = new ModifyRequest(
                            dn,
                            DirectoryAttributeOperation.Replace,
                            LdapAttribute.UnicodePassword,
                            pwdBytes
                        );

                        var pwdResponse = (ModifyResponse)_connection.SendRequest(pwdRequest);

                        if (pwdResponse.ResultCode != ResultCode.Success)
                        {
                            return new LdapResult
                            {
                                Success = false,
                                Message = $"Password change failed: {pwdResponse.ResultCode} - {pwdResponse.ErrorMessage}"
                            };
                        }

                        continue; // Skip to next attribute
                    }

                    // For normal attributes
                    var modAttr = new DirectoryAttribute(attr.Name);
                    foreach (var val in attr)
                    {
                        if (val is byte[] bytes)
                        {
                            modAttr.Add(bytes);
                        }
                        else if (val != null)
                        {
                            modAttr.Add(val.ToString());
                        }
                    }

                    var request = new ModifyRequest(
                        dn,
                        DirectoryAttributeOperation.Replace,
                        attr.Name,
                        attr.Cast<object>().ToArray()
                    );

                    var response = (ModifyResponse)_connection.SendRequest(request);

                    if (response.ResultCode != ResultCode.Success)
                    {
                        return new LdapResult
                        {
                            Success = false,
                            Message = $"Modify failed for {attr.Name}: {response.ResultCode} - {response.ErrorMessage}"
                        };
                    }
                }

                return new LdapResult
                {
                    Success = true,
                    Message = "All modifications successful."
                };
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

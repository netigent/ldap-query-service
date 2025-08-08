using Microsoft.Extensions.Options;
using Netigent.Utils.Ldap.Constants;
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

        /// <summary>
        /// Modifies an LDAP entry.
        /// </summary>
        /// <param name="dn">cn=John Doe,ou=Users,dc=example,dc=com</param>
        /// <param name="directoryAttributes"></param>
        /// <returns></returns>
        private LdapResult ModifyLdap(string dn, IList<DirectoryAttribute> directoryAttributes)
        {

            string newUsername = "testuser";
            string firstName = "Test";
            string lastName = "User";
            string userPassword = "SecurePassword123!";
            string ldapPath = $"LDAP://{_config.FullDNS}:{_config.Port}/OU=AADDC Users,DC=ibks,DC=co";
            using (DirectoryEntry directoryEntry = new DirectoryEntry(ldapPath, _config.ServiceAccount, _config.ServiceKey))
            {
                DirectoryEntry newUser = directoryEntry.Children.Add($"CN={firstName} {lastName}", "user");

                // Set user properties
                newUser.Properties["userPrincipalName"].Value = $"{newUsername}@ibks.co";
                newUser.Properties["sAMAccountName"].Value = newUsername;
                newUser.Properties["givenName"].Value = firstName;
                newUser.Properties["sn"].Value = lastName;
                newUser.Properties["displayName"].Value = $"{firstName} {lastName}";
                newUser.Properties["description"].Value = "Test user created via C#";

                // Enable the account (userAccountControl: 512 = normal account, enabled)
                newUser.Properties["userAccountControl"].Value = 512;

                // Commit changes to create the user
                newUser.CommitChanges();

                // Set the password
                newUser.Invoke("SetPassword", new object[] { userPassword });

                // Commit password change
                newUser.CommitChanges();

                Console.WriteLine("User created successfully!");
            }



            string dn2 = "CN=James O'Neill,OU=AADDC Users,DC=ibks,DC=co";
            string host = "corp.ibks.co";
            int port = 636;

            var identifier = new LdapDirectoryIdentifier(host, port, true, false);
            var credential = new NetworkCredential(_config.ServiceAccount, _config.ServiceKey);

            using var connection = new LdapConnection(identifier, credential, AuthType.Basic)
            {
                SessionOptions =
                {
                    SecureSocketLayer = true,
                    ProtocolVersion = 3
                }
            };

            connection.Bind(); // Throws LdapException if there's a problem
            Console.WriteLine("Successfully bound");

            // Now, to modify an attribute:
            var request = new ModifyRequest(
                dn,
                DirectoryAttributeOperation.Replace,
                    //"userAccountControl",
                    //"544"
                    "description",
    "Test update from LdapConnection"
            );


            DirectoryResponse response = _connection.SendRequest(request);

            DirectoryEntry entry = null;
            try
            {
                // Bind to the object using DirectoryEntry
                const AuthenticationTypes authenticationTypes = AuthenticationTypes.Secure |
                AuthenticationTypes.Sealing | AuthenticationTypes.ServerBind;

                // (SearchLdap(string.Format(LdapFilter.FindGroupByDn, dn), AttributeList.User)[0]).

                entry = new DirectoryEntry($"LDAPS://{this._config.FullDNS}:{this._config.Port}/{dn}", _config.ServiceAccount, _config.ServiceKey, authenticationTypes);

                // Iterate over each DirectoryAttribute
                foreach (var directoryAttribute in directoryAttributes)
                {
                    // Skipping certain attributes like UserPrincipalName and SAMAccountName
                    if (
                        directoryAttribute.Name == LdapAttribute.UserPrincipalName
                        || directoryAttribute.Name == LdapAttribute.SAMAccountName)
                    {
                        continue;
                    }

                    // Retrieve attribute value as a string
                    string attributeValue = GetAttributeValue(directoryAttribute);

                    // Handle password updates (needs to be Unicode bytes)
                    if (directoryAttribute.Name == LdapAttribute.UnicodePassword)
                    {
                        // Set password using the 'Invoke' method for password-related attributes
                        entry.Invoke("SetPassword", new object[] { attributeValue });
                    }
                    else
                    {
                        // Check if the attribute already exists in the DirectoryEntry
                        if (entry.Properties.Contains(directoryAttribute.Name))
                        {
                            // Replace the existing value
                            entry.Properties[directoryAttribute.Name].Value = attributeValue;
                        }
                        else
                        {
                            // Add new attribute if it doesn't exist
                            entry.Properties[directoryAttribute.Name].Add(attributeValue);
                        }
                    }
                }

                // Commit the changes to the DirectoryEntry
                entry.CommitChanges();

                return new LdapResult
                {
                    Success = true,
                    Message = "Modification successful."
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
            finally
            {
                if (entry != null)
                {
                    entry.Dispose();
                }
            }

            /*
            try
            {
                // Grab existing object, with just attributes we're trying to mod
                // This way we can tell if we're doing replace / add
                SearchResultEntry existing = SearchLdap(
                        string.Format(LdapFilter.AllByDn, dn),
                        directoryAttributes.Select(x => x.Name).ToArray())[0];

                // Lets Build the modify request
                ModifyRequest modifyRequest = new ModifyRequest(dn);

                // Convert each DirectoryAttribute into DirectoryAttributeModification
                foreach (DirectoryAttribute directoryAttribute in directoryAttributes)
                {
                    // Skipped Items from Modify Request
                    if (directoryAttribute.Name == LdapAttribute.UserPrincipalName
                        || directoryAttribute.Name == LdapAttribute.SAMAccountName)
                    {
                        continue;
                    }

                    // Grab String Value
                    string attributeValue = GetAttributeValue(directoryAttribute);

                    // Build Modification
                    DirectoryAttributeModification modAttribute = new DirectoryAttributeModification
                    {
                        Name = directoryAttribute.Name,
                        Operation = existing.Attributes.Contains(directoryAttribute.Name)
                            ? DirectoryAttributeOperation.Replace
                            : DirectoryAttributeOperation.Add,
                    };

                    // Seems a few keys need to be byte
                    if (directoryAttribute.Name == LdapAttribute.UnicodePassword)
                    {
                        modAttribute.Add(Encoding.Unicode.GetBytes(attributeValue));
                    }
                    else
                    {
                        modAttribute.Add(attributeValue);
                    }

                    // Append to request
                    modifyRequest.Modifications.Add(modAttribute);
                }

                DirectoryResponse modifyResponse = _connection.SendRequest(modifyRequest) as ModifyResponse;
                return new LdapResult
                {
                    Success = modifyResponse.ResultCode == ResultCode.Success,
                    Message = modifyResponse.ErrorMessage,
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
            */
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

        /// <summary>
        /// Get Value.
        /// </summary>
        /// <param name="attribute"></param>
        /// <returns></returns>
        private string GetAttributeValue(DirectoryAttribute attribute)
        {
            if (attribute == null || attribute.Count == 0)
            {
                return string.Empty;
            }

            return attribute[0].ToString();
        }
        #endregion
    }
}

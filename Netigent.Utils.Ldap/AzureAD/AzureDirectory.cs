using Netigent.Utils.Ldap.Constants;
using Netigent.Utils.Ldap.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Netigent.Utils.Ldap.AzureAD
{
    internal class GraphService(string tenantId, string clientId, string clientSecret) : IDisposable
    {
        // Endpoints
        private const string GraphBaseUrl = "https://graph.microsoft.com/v1.0";
        private const string AzureScope = "https://graph.microsoft.com/.default";
        private const string UsersUrl = $"{GraphBaseUrl}/users";

        private readonly string _tenantId = tenantId ?? throw new ArgumentNullException(nameof(tenantId));
        private readonly string _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
        private readonly string _clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));

        private readonly HttpClient _httpClient = new HttpClient();

        private string? _accessToken;
        private DateTime _tokenExpiry = DateTime.MinValue;

        /// <summary>
        /// Set AzureAD account as enabled or disabled.
        /// </summary>
        /// <param name="ldapUser"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        internal async Task<LdapResult<string>> SetAccountEnabledAsync(LdapUser ldapUser, bool enabled)
        {
            // Null Check
            if (ldapUser == null) return new LdapResult<string> { Message = "Null Parameter: ldapUser" };

            // Access Token Check
            var accessResult = await HasAccessToken();
            if (!accessResult.Success) return new LdapResult<string> { Message = accessResult.Message };

            // Fetch from Graph to confirm ok to proceed
            var foundUserResult = await TryGetUserAsync(ldapUser.AzureId.ToString());
            if (foundUserResult == null || !foundUserResult.Success || foundUserResult.Data == null)
                return new LdapResult<string> { Message = $"User '{ldapUser.UserPrincipalName}' - {ldapUser.ObjectGUID} not found" };

            if (foundUserResult.Data.OnPremisesSyncEnabled == true)
                return new LdapResult<string> { Message = $"User '{ldapUser.UserPrincipalName}' - {ldapUser.ObjectGUID} is synchronized from on-premises and cannot be modified." };

            try
            {
                var updateData = new { accountEnabled = enabled };
                var json = JsonSerializer.Serialize(updateData);

                var request = new HttpRequestMessage(new HttpMethod("PATCH"), UserUrl(foundUserResult.Data.Id))
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } },
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                var response = await _httpClient!.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    var reason = response.StatusCode == System.Net.HttpStatusCode.Forbidden
                        ? "Insufficient privileges. App registration needs 'User Administrator' role"
                        : $"HTTP {response.StatusCode}: {errorContent}";

                    return new LdapResult<string> { Data = foundUserResult.Data.UserPrincipalName, Message = $"Failed setting AccountEnabled={enabled}. Reason: {reason}" };
                }

                return new LdapResult<string> { Data = foundUserResult.Data.UserPrincipalName, Success = true, Message = $"Account {(enabled ? "Enabled" : "Disabled")}" };
            }
            catch (Exception ex)
            {
                return new LdapResult<string> { Data = foundUserResult.Data.UserPrincipalName, Message = $"Failed setting AccountEnabled={enabled}. Reason: {ex.Message}" };
            }
        }

        internal async Task<LdapResult<string>> UpsertUserAsync(GraphUserUpsertRequest request, LdapUser? ldapUser)
        {
            // Access Token Check
            var accessResult = await HasAccessToken();
            if (!accessResult.Success) return new LdapResult<string> { Message = accessResult.Message };

            // Fetch from Graph to confirm ok to proceed
            var foundUserResult = await TryGetUserAsync(request.UserPrincipalName);

            if (foundUserResult?.Data?.OnPremisesSyncEnabled == true)
                return new LdapResult<string> { Message = $"User '{ldapUser.UserPrincipalName}' - {ldapUser.ObjectGUID} is synchronized from on-premises and cannot be modified." };

            if (foundUserResult == null || !foundUserResult.Success || foundUserResult.Data == null)
            {
                // New 
                if (string.IsNullOrWhiteSpace(request.InitialPassword))
                {
                    throw new InvalidOperationException("InitialPassword must be provided when creating a new user in Azure AD.");
                }

                var newUser = new GraphUser
                {
                    AccountEnabled = request.AccountEnabled ?? true,
                    DisplayName = request.DisplayName,
                    MailNickname = GenerateMailNickname(request),
                    UserPrincipalName = request.UserPrincipalName ?? request.Mail,
                    PasswordProfile = new GraphNewPassword
                    {
                        Password = request.InitialPassword,
                    }
                };

                var json = JsonSerializer.Serialize(newUser, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

                var httpRequest = new HttpRequestMessage(HttpMethod.Post, UsersUrl)
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } },
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                var response = await _httpClient!.SendAsync(httpRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return new LdapResult<string> { Message = $"Failed to create user. HTTP {response.StatusCode}: {responseContent}" };
                }
            }

            // Lets Confirm accoutn was created.
            foundUserResult = await TryGetUserAsync(request.UserPrincipalName);
            if (foundUserResult == null || !foundUserResult.Success || foundUserResult.Data == null)
                return new LdapResult<string> { Message = $"Created Account {request.UserPrincipalName}, not availabel for update" };

            // Existing
            var updateData = new Dictionary<string, object?>();
            if (!string.IsNullOrWhiteSpace(request.City)) updateData["city"] = request.City;
            if (!string.IsNullOrWhiteSpace(request.Company)) updateData["companyName"] = request.Company;
            if (!string.IsNullOrWhiteSpace(request.Department)) updateData["department"] = request.Department;
            if (!string.IsNullOrWhiteSpace(request.DisplayName)) updateData[LdapAttribute.DisplayName] = request.DisplayName;
            if (!string.IsNullOrWhiteSpace(request.GivenName)) updateData[LdapAttribute.FirstName] = request.GivenName;
            if (!string.IsNullOrWhiteSpace(request.JobTitle)) updateData["jobTitle"] = request.JobTitle;
            if (!string.IsNullOrWhiteSpace(request.Mail)) updateData[LdapAttribute.Mail] = request.Mail;
            if (!string.IsNullOrWhiteSpace(request.Mobile)) updateData["mobilePhone"] = request.Mobile;
            if (!string.IsNullOrWhiteSpace(request.Office)) updateData["officeLocation"] = request.Office;
            if (!string.IsNullOrWhiteSpace(request.PostalCode)) updateData["postalCode"] = request.PostalCode;
            if (!string.IsNullOrWhiteSpace(request.Street)) updateData["streetAddress"] = request.Street;
            if (!string.IsNullOrWhiteSpace(request.Surname)) updateData["surname"] = request.Surname;

            if (updateData.Count > 0)
            {
                var json = JsonSerializer.Serialize(updateData);
                var updateRequest = new HttpRequestMessage(new HttpMethod("PATCH"), UserUrl(foundUserResult.Data.Id))
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } },
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                var updateResponse = await _httpClient!.SendAsync(updateRequest);
                if (!updateResponse.IsSuccessStatusCode)
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    return new LdapResult<string> { Data = ldapUser.UserPrincipalName, Message = $"Failed to update user. HTTP {updateResponse.StatusCode}: {errorContent}" };
                }
            }

            // Handle password change
            if (!string.IsNullOrWhiteSpace(request.InitialPassword))
            {
                await UpdatePasswordAsync(ldapUser.AzureOrObjectID, request.InitialPassword);
            }

            return new LdapResult<string>
            {
                Success = true,
                Data = ldapUser.UserPrincipalName,
                Message = "Updated Account"
            };
        }

        internal async Task<LdapResult> UpdatePasswordAsync(Guid userId, string password)
        {
            var passwordUpdate = new GraphUser
            {
                PasswordProfile = new GraphNewPassword
                {
                    Password = password,
                }
            };

            var json = JsonSerializer.Serialize(passwordUpdate, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
            var updateRequest = new HttpRequestMessage(new HttpMethod("PATCH"), UserUrl(userId))
            {
                Headers = { { "Authorization", $"Bearer {_accessToken}" } },
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            var updateResponse = await _httpClient!.SendAsync(updateRequest);
            var errorContent = await updateResponse.Content.ReadAsStringAsync();

            return new LdapResult
            {
                Success = updateResponse.IsSuccessStatusCode,
                Message = errorContent.Contains("accessDenied")
                    ? $"App {_clientId} in {_tenantId} - {LdapWarnings.AzurePasswordPermissions}"
                    : errorContent
            };
        }

        // Alternative implementation - Individual member addition (if bulk fails)
        internal async Task<LdapResult> AddMemberAsync(Guid userId, Guid groupId)
        {
            if (userId == default || groupId == default)
            {
                return new LdapResult { Message = "User and GroupId required" };
            }

            var accessResult = await HasAccessToken();
            if (!accessResult.Success) return accessResult;

            try
            {
                // Body must contain the "@odata.id" reference to the user object
                var body = new ODataReference
                {
                    ODataId = $"{GraphBaseUrl}/directoryObjects/{Uri.EscapeDataString(userId.ToString())}"
                };

                var request = new HttpRequestMessage(HttpMethod.Post,
                    $"{GraphBaseUrl}/groups/{Uri.EscapeDataString(groupId.ToString())}/members/$ref")
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } },
                    Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
                };

                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return new LdapResult
                    {
                        Message = $"Failed to add userId {userId} to groupId {groupId}. HTTP {response.StatusCode}: {errorContent}"
                    };
                }

                return new LdapResult { Success = true, Message = $"Added userId {userId} to groupId {groupId}." };
            }
            catch (Exception ex)
            {
                return new LdapResult { Message = $"Error adding userId {userId} to groupId {groupId}: {ex.Message}" };
            }
        }

        internal async Task<LdapResult> RemoveMemberAsync(Guid userId, Guid groupId)
        {
            if (userId == default || groupId == default)
            {
                return new LdapResult { Message = "User and GroupId required" };
            }

            var accessResult = await HasAccessToken();
            if (!accessResult.Success) return accessResult;

            try
            {
                // This matches the Microsoft Graph documentation exactly
                var request = new HttpRequestMessage(HttpMethod.Delete,
                    $"{GraphBaseUrl}/groups/{Uri.EscapeDataString(groupId.ToString())}/members/{Uri.EscapeDataString(userId.ToString())}/$ref")
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } }
                };

                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return new LdapResult
                    {
                        Message = $"Failed to remove userId {userId.ToString()} from groupId {groupId.ToString()}. HTTP {response.StatusCode}: {errorContent}"
                    };
                }

                return new LdapResult { Success = true, Message = $"Removed userId {userId.ToString()} from groupId {groupId.ToString()}." };
            }
            catch (Exception ex)
            {
                return new LdapResult { Message = $"Error removing userId {userId.ToString()} from groupId {groupId.ToString()}: {ex.Message}" };
            }
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
            _accessToken = null;
        }

        #region Private Functions

        private string GenerateMailNickname(GraphUserUpsertRequest request)
        {
            if (!string.IsNullOrWhiteSpace(request.UserPrincipalName))
                return request.UserPrincipalName.Split('@')[0];

            if (!string.IsNullOrWhiteSpace(request.Mail))
                return request.Mail.Split('@')[0];

            return (request.GivenName + "." + request.Surname).Trim('.', ' ');
        }


        private async Task<LdapResult> HasAccessToken()
        {
            if (!string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _tokenExpiry)
            {
                return new LdapResult { Success = true };
            }

            var tokenRequestBody = new List<KeyValuePair<string, string>>
            {
                new("client_id", _clientId),
                new("client_secret", _clientSecret),
                new("scope", AzureScope),
                new("grant_type", "client_credentials")
            };

            var request = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token")
            {
                Content = new FormUrlEncodedContent(tokenRequestBody)
            };

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return new LdapResult { Message = $"Failed to get access token: {response.StatusCode} - {responseContent}" };
            }

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent);
            if (string.IsNullOrEmpty(tokenResponse?.AccessToken))
            {
                return new LdapResult { Message = "Invalid token response received" };
            }

            _accessToken = tokenResponse.AccessToken;
            _tokenExpiry = DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn - 300);

            return new LdapResult
            {
                Success = !string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _tokenExpiry,
                Message = "Aquired New Token"
            };
        }

        private string UserUrl(string upn) => $"{UsersUrl}/{Uri.EscapeDataString(upn)}";
        private string UserUrl(Guid azureObjectId) => $"{UsersUrl}/{Uri.EscapeDataString(azureObjectId.ToString())}";

        // https://learn.microsoft.com/en-us/graph/api/authenticationmethod-resetpassword?view=graph-rest-1.0&tabs=http
        private string PasswordResetUrl(string upn) => $"{UsersUrl}/{Uri.EscapeDataString(upn)}/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword";
        private string PasswordResetUrl(Guid azureObjectId) => $"{UsersUrl}/{Uri.EscapeDataString(azureObjectId.ToString())}/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword";

        private async Task<LdapResult<GraphUser>> TryGetUserAsync(Guid azureObjectId) =>
            await TryGetUserAsync(azureObjectId.ToString());

        private async Task<LdapResult<GraphUser>> TryGetUserAsync(string upn)
        {
            // Access Token Check
            var accessResult = await HasAccessToken();
            if (!accessResult.Success) return new LdapResult<GraphUser> { Message = accessResult.Message };

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, UserUrl(upn))
                {
                    Headers = { { "Authorization", $"Bearer {_accessToken}" } }
                };

                var response = await _httpClient!.SendAsync(request);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new LdapResult<GraphUser> { Message = "User not found" };
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new LdapResult<GraphUser> { Message = $"Failed to get user: HTTP {response.StatusCode}" };
                }

                var user = JsonSerializer.Deserialize<GraphUser>(responseContent);
                return new LdapResult<GraphUser> { Data = user, Success = true, Message = $"Found user {upn}" };
            }
            catch (Exception ex)
            {
                return new LdapResult<GraphUser> { Message = $"Error getting user: {ex.Message}" };
            }
        }
        #endregion
    }
}


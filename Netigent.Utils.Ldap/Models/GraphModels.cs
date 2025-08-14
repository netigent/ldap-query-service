using Netigent.Utils.Ldap.Constants;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Netigent.Utils.Ldap.Models
{
    // Extended upsert request that maps to your existing parameters
    public record GraphUserUpsertRequest
    {
        public string? ObjectId { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? DisplayName { get; set; }
        public string? GivenName { get; set; }
        public string? Surname { get; set; }
        public string? Mail { get; set; }
        public string? JobTitle { get; set; }
        public bool? AccountEnabled { get; set; }
        public string? InitialPassword { get; set; }
        public bool ForceChangePasswordNextSignIn { get; set; } = true;

        // Additional properties to match your LDAP interface
        public string? Company { get; set; }
        public string? Department { get; set; }
        public string? Office { get; set; }
        public string? Mobile { get; set; }
        public string? Description { get; set; }
        public string? Street { get; set; }
        public string? City { get; set; }
        public string? PostalCode { get; set; }
    }

    // Graph API models (keeping these internal to the service)
    internal class ODataReference
    {
        [JsonPropertyName("@odata.id")]
        public string ODataId { get; set; }
    }

    internal class GraphUser
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName(LdapAttribute.UserPrincipalName)]
        public string? UserPrincipalName { get; set; }

        [JsonPropertyName(LdapAttribute.DisplayName)]
        public string? DisplayName { get; set; }

        [JsonPropertyName(LdapAttribute.FirstName)]
        public string? GivenName { get; set; }

        [JsonPropertyName("surname")]
        public string? Surname { get; set; }

        [JsonPropertyName(LdapAttribute.Mail)]
        public string? Mail { get; set; }

        [JsonPropertyName(LdapAttribute.JobTitle)]
        public string? JobTitle { get; set; }

        [JsonPropertyName("accountEnabled")]
        public bool? AccountEnabled { get; set; }

        [JsonPropertyName("onPremisesSyncEnabled")]
        public bool? OnPremisesSyncEnabled { get; set; }

        [JsonPropertyName("mailNickname")]
        public string? MailNickname { get; set; }

        [JsonPropertyName("passwordProfile")]
        public GraphNewPassword? PasswordProfile { get; set; }

        [JsonPropertyName("companyName")]
        public string? CompanyName { get; set; }

        [JsonPropertyName(LdapAttribute.Department)]
        public string? Department { get; set; }

        [JsonPropertyName("officeLocation")]
        public string? OfficeLocation { get; set; }

        [JsonPropertyName("mobilePhone")]
        public string? MobilePhone { get; set; }

        [JsonPropertyName(LdapAttribute.Street)]
        public string? StreetAddress { get; set; }

        [JsonPropertyName("city")]
        public string? City { get; set; }

        [JsonPropertyName("postalCode")]
        public string? PostalCode { get; set; }
    }

    internal class GraphNewPassword
    {
        [JsonPropertyName("password")]
        public string? Password { get; set; }

        [JsonPropertyName("forceChangePasswordNextSignIn")]
        public bool ForceChangePasswordNextSignIn { get; set; }
    }

    internal class GraphUsersResponse
    {
        [JsonPropertyName("value")]
        public List<GraphUser>? Value { get; set; }
    }

    internal class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }
}

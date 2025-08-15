namespace Netigent.Utils.Ldap.Models
{
    public class LdapConfig
    {
        public static string Section { get; } = "LDAP";
        public string FullDNS { get; set; }
        public string SearchBase { get; set; }
        public int Port { get; set; } = 636;
        public bool UseSSL { get; set; } = true;
        public string UserLoginDomain { get; set; }

        public string ServiceAccount { get; set; } = string.Empty;

        public string ServiceKey { get; set; } = string.Empty;

        /// <summary>
        /// Max number of times to try login against LDAP when unavailable returned 
        /// before giving up.
        /// </summary>
        public int MaxTries { get; set; } = 1;

        /// <summary>
        /// Period to delay next attempt in milliseconds
        /// </summary>
        public int RetryDelayMs { get; set; } = 300;

        public string? AzureTenentId { get; set; }
        public string? AzureClientId { get; set; }
        public string? AzureClientSecret { get; set; }

        public bool? ShouldThrowErrors { get; set; } = false;

    }
}

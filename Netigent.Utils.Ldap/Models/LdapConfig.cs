namespace Netigent.Utils.Ldap.Models
{
	public class LdapConfig
    {
        public static string Section { get; } = "LDAP";
        public string FullDNS { get; set; }
        public string SearchBase { get; set; }
        public int Port { get; set; }
		public bool UseSSL { get; set; }
        public string UserLoginDomain { get; set; }

        /// <summary>
        /// Max number of times to try login against LDAP when unavailable returned 
        /// before giving up.
        /// </summary>
        public int MaxTries { get; set; } = 1;

        /// <summary>
        /// Period to delay next attempt in milliseconds
        /// </summary>
        public int RetryDelayMs { get; set; } = 300;
    }
}

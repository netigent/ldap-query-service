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
    }
}

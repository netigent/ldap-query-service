namespace Netigent.Utils.LdapTestApp
{
    public class NewUserConfig
    {
        public static string Section { get; } = "NewUser";

        public string Email { get; set; }

        public string Upn { get; set; }

        public string Telephone { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public string Company { get; set; } = string.Empty;

        public string JobTitle { get; set; } = string.Empty;

        public string Department { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;

    }
}

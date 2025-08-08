namespace Netigent.Utils.Ldap.Models
{
    public record LdapResult<T> : LdapResult
    {
        public T Data { get; set; }
    }

    public record LdapResult
    {
        public bool Success { get; set; } = false;

        public string Message { get; set; } = string.Empty;
    }
}

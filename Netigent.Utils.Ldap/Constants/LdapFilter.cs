namespace Netigent.Utils.Ldap.Constants
{
    public class LdapFilter
    {
        public const string AllByDn = "(&(distinguishedName={0}))";

        public const string AllGroups = "(&(objectClass=group))";
        public const string FindGroupByDisplayname = "(&(objectClass=group)(displayName={0}))";
        public const string FindGroupByDn = "(&(objectClass=group)(distinguishedName={0}))";
        public const string FindGroupBySam = "(&(objectClass=group)(sAMAccountName={0}))";
        // public const string FindGroupByGuid = "(&(objectClass=group)(objectGUID={0}))";
        public const string FindGroupByAzureIdOrObjectId = "(&(objectClass=group)(|(msDS-aadObjectId={0})(objectGUID={0})(msDS-aadObjectId={1})(objectGUID={1})))";

        public const string AllUsers = "(&(objectCategory=person)(objectCategory=user))";
        public const string FindUserByEmail = "(&(objectClass=person)(objectCategory=user)(mail={0}))";
        public const string FindUserByDisplayname = "(&(objectClass=person)(objectCategory=user)(displayName={0}))";
        public const string FindUserByDn = "(&(objectClass=person)(objectCategory=user)(distinguishedName={0}))";
        public const string FindUserBySam = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))";
        // public const string FindUserByGuid = "(&(objectClass=person)(objectCategory=user)(objectGUID={0}))";
        public const string FindUserByUpn = "(&(objectClass=person)(objectCategory=user)(userPrincipalName={0}))";
        public const string FindUserByAzureIdOrObjectId = "(&(objectClass=person)(objectCategory=user)(|(msDS-aadObjectId={0})(objectGUID={0})(msDS-aadObjectId={1})(objectGUID={1})))";

        public const string AllMembersOfByGroupDn = "(&(objectCategory=Person)(objectClass=User)((memberOf={0})))";
    }
}

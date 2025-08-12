using Microsoft.Extensions.Configuration;
using Netigent.Utils.Ldap;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;

namespace Netigent.Utils.LdapTestApp
{
    class Program
    {
        static ILdapQueryService ldapService;

        static void Main(string[] args)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false)
                .Build();

            // Instantiate your LDAP service implementation (replace with your actual class & constructor)
            var ldapConfig = config.GetSection(LdapConfig.Section).Get<LdapConfig>();
            ldapService = new LdapQueryService(ldapConfig);

            IList<LdapUser>? ldapUsers = new List<LdapUser>();
            IList<LdapGroup>? ldapGroups = new List<LdapGroup>();

            // Read test inputs
            var t = config.GetSection(NewUserConfig.Section).Get<NewUserConfig>();

            Console.WriteLine("===== Starting LDAP Service Tests =====");
            #region Group Tests
            RunTest("GetGroups", () =>
            {
                ldapGroups = ldapService.GetGroups();
                if (ldapGroups == null) throw new Exception("Returned null");
                Console.WriteLine($" - Found {ldapGroups.Count} groups");
                int count = 0;
                foreach (var g in ldapGroups)
                {
                    if (++count > 500) break;
                    Console.WriteLine($"   {count}. Group: {g.DistinguishedName} - {g.DisplayName}");
                }
            }, false);

            Console.WriteLine($"Pick Group Id");
            int grpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
            LdapGroup g = ldapGroups[grpId - 1];

            RunTest($"GetGroup - by DisplayName '{g.DisplayName}'", () =>
            {
                var group = ldapService.GetGroup(g.DisplayName);
                if (group == null) throw new Exception("Group not found");
                Console.WriteLine($" - Found group: {group.DistinguishedName}");
            }, false);

            RunTest($"GetGroup - by DN  '{g.DistinguishedName}'", () =>
            {
                var group = ldapService.GetGroup(g.DistinguishedName, LdapQueryAttribute.Dn);
                if (group == null) throw new Exception("Group not found");
                Console.WriteLine($" - Found group: {group.DistinguishedName}");
            }, false);
            #endregion

            #region USer Tests
            //***************************** Users *************/

            RunTest("GetUsers", () =>
            {
                ldapUsers = ldapService.GetUsers();
                if (ldapUsers == null) throw new Exception("Returned null");

                Console.WriteLine($" - Found {ldapUsers.Count} users");
                int count = 0;
                foreach (var u in ldapUsers)
                {
                    if (++count > 500) break;
                    Console.WriteLine($"   {count}. User: {u.DistinguishedName} - {u.Mail} - {u.UserPrincipalName}");
                }
            }, false);

            Console.WriteLine($"------User Based Operations-------------");
            Console.WriteLine($"Pick User Id");
            int userId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
            LdapUser u = ldapUsers[userId - 1];

            RunTest("MemberOf", () =>
            {
                bool isMember = ldapService.IsMemberOf(u.UserPrincipalName, g.DistinguishedName, LdapQueryAttribute.Dn);
                Console.WriteLine($" - User '{u.UserPrincipalName} 'is {(isMember ? "" : "NOT ")} a member of group '{g.DistinguishedName}'");
            }, false);

            Console.WriteLine($"Enter your password for '{u.Mail}'");
            string password = Console.ReadLine() ?? string.Empty;

            RunTest("UserLogin - By Email", () =>
            {
                var result = ldapService.UserLogin(u.Mail, password);
                if (result.Success)
                {
                    Console.WriteLine($" - Logged in user: {result.Data.UserPrincipalName} - {result.Data.DisplayName} - {result.Data.ObjectGUID} - {result.Data.AzureObjectId}");
                }
                else
                {
                    throw new Exception(result.Message);
                }
            }, false);

            RunTest("UserLogin - By UPN", () =>
            {
                var result = ldapService.UserLogin(u.UserPrincipalName, password);
                if (result.Success)
                {
                    Console.WriteLine($" - Logged in user: {result.Data.UserPrincipalName} - {result.Data.DisplayName} - {result.Data.ObjectGUID} - {result.Data.AzureObjectId}");
                }
                else
                {
                    throw new Exception(result.Message);
                }
            }, false);

            RunTest("DisableUser", () =>
            {
                var result = ldapService.DisableUser(u.UserPrincipalName);
                if (!result.Success)
                    throw new Exception(result.Message);
            });

            RunTest("EnableAndUnlockUser", () =>
            {
                var result = ldapService.EnableAndUnlockUser(u.UserPrincipalName);
                if (!result.Success)
                    throw new Exception(result.Message);
            });

            RunTest("UpsertUser (Add)", () =>
            {
                Console.WriteLine("New User Password??");
                string? newPassword = Console.ReadLine();

                var result = ldapService.UpsertUser(
                    username: t.Upn,
                    setPassword: newPassword,
                    email: t.Email,
                    displayName: t.DisplayName,
                    company: t.Company,
                    jobTitle: t.JobTitle,
                    mobile: t.Telephone,
                    department: t.Department,
                    description: t.Description);

                if (!result.Success)
                    throw new Exception(result.Message);

                Console.WriteLine("Add Result: " + result.Message);
            });

            RunTest("UpsertUser (Mod)", () =>
            {
                string tStamp = DateTime.Now.ToString("HHmmss");
                Console.WriteLine("Mod Stamp = " + tStamp);

                var result = ldapService.UpsertUser(
                    username: u.UserPrincipalName,
                    setPassword: "",
                    email: u.Mail,
                    displayName: u.DisplayName + tStamp,
                    company: u.Company + tStamp,
                    jobTitle: u.JobTitle + tStamp,
                    mobile: u.MobilePhone + tStamp,
                    department: u.Department + tStamp,
                    street: u.Street + tStamp,
                    city: u.City + tStamp,
                    zip: u.ZipPostalCode + tStamp,
                    description: u.OfficeName + tStamp);

                if (!result.Success)
                    throw new Exception(result.Message);

                Console.WriteLine("Mod Result: " + result.Message);
            });

            RunTest("ResetPassword", () =>
            {
                Console.WriteLine($"Reset Password for {u.DistinguishedName}?");
                string? resetPassword = Console.ReadLine();

                if (resetPassword?.Length > 0)
                {
                    var result = ldapService.ResetPassword(u.DistinguishedName, resetPassword.Trim());
                    if (!result.Success)
                        throw new Exception(result.Message);

                    Console.WriteLine("Password Reset: " + result.Message);
                }
            });

            RunTest("Add GRoup", () =>
            {
                Console.WriteLine($"Add to - Group Id?? ");
                int agrpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
                LdapGroup ag = ldapGroups[agrpId - 1];

                if (agrpId > 0)
                {
                    var result = ldapService.AddToGroup(u.DistinguishedName, ag.DistinguishedName);
                    if (!result.Success)
                        throw new Exception(result.Message);

                    Console.WriteLine("Added Result: " + result.Message);
                }
            });


            RunTest("Remove Group", () =>
            {
                Console.WriteLine($"Remove - Group Id?? ");
                int agrpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
                LdapGroup ag = ldapGroups[agrpId - 1];

                if (agrpId > 0)
                {
                    var result = ldapService.RemoveGroup(u.DistinguishedName, ag.DistinguishedName);
                    if (!result.Success)
                        throw new Exception(result.Message);

                    Console.WriteLine("Removed Result: " + result.Message);
                }
            });

            #endregion

            Console.WriteLine("===== LDAP Service Tests Completed ===== (Press Any Key to End)");
            Console.ReadKey();
        }

        static void RunTest(string testName, Action testAction, bool pause = true)
        {
            Console.Write($"{testName} - ");
            try
            {
                testAction();

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed - {ex.Message}");
            }

            if (pause)
            {
                Console.WriteLine("Passed (Press Any Key to Continue)");
                Console.ReadKey();
            }
        }
    }
}

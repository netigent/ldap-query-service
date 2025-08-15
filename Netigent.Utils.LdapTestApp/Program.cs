using Microsoft.Extensions.Configuration;
using Netigent.Utils.Ldap;
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

            if (ldapService == null || !ldapService.HasServiceAccount)
            {
                throw new Exception(ldapService.ServiceAccountMessage);
            }

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
                    Console.WriteLine($"   {count}. Group: {g.DisplayName} | {g.AzureOrObjectID.ToString()} | {g.DistinguishedName}");
                }
            }, false);

            Console.WriteLine($"Pick Group Id");
            int grpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
            LdapGroup g = ldapGroups[grpId - 1];

            RunTest($"GetGroup - by DisplayName '{g.DisplayName}'", () =>
            {
                var group = ldapService.GetGroup(g.DisplayName);
                if (group == null) throw new Exception("Group not found");
                Console.WriteLine($" - Found group: {group.Data.DistinguishedName}");
            }, false);

            RunTest($"GetGroup - by DN  '{g.DistinguishedName}'", () =>
            {
                var group = ldapService.GetGroup(g.DistinguishedName);
                if (group == null) throw new Exception("Group not found");
                Console.WriteLine($" - Found group: {group.Data.DistinguishedName}");
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
                    Console.WriteLine($"   {count}. User: {u.UserPrincipalName} | {u.AzureOrObjectID.ToString()} | {u.DistinguishedName}");
                }
            }, false);

            Console.WriteLine($"------User Based Operations-------------");
            Console.WriteLine($"Pick User Id");
            int userId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
            LdapUser u = ldapUsers[userId - 1];

            RunTest("MemberOf BY DN", () =>
            {
                bool isMember = ldapService.IsMemberOf(u.UserPrincipalName, g.AzureId.ToString());
                Console.WriteLine($" - User '{u.UserPrincipalName} 'is {(isMember ? "" : "NOT ")} a member of group '{g.DistinguishedName}'");
            }, false);

            RunTest("MemberOf BY GroupId", () =>
            {
                bool isMember = ldapService.IsMemberOf(u.UserPrincipalName, g.ObjectGUID.ToString());
                Console.WriteLine($" - User '{u.UserPrincipalName} 'is {(isMember ? "" : "NOT ")} a member of group '{g.DistinguishedName}'");
            }, false);


            Console.WriteLine($"Enter your password for '{u.Mail}'");
            string password = Console.ReadLine() ?? string.Empty;

            RunTest("UserLogin - By Email", () =>
            {
                var result = ldapService.UserLogin(u.Mail, password);
                if (result.Success)
                {
                    Console.WriteLine($" - Logged in user: {result.Data.UserPrincipalName} - {result.Data.DisplayName} - {result.Data.ObjectGUID} - {result.Data.AzureId}");
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
                    Console.WriteLine($" - Logged in user: {result.Data.UserPrincipalName} - {result.Data.DisplayName} - {result.Data.ObjectGUID} - {result.Data.AzureId}");
                }
                else
                {
                    throw new Exception(result.Message);
                }
            }, false);

            RunTest("DisableUser", async () =>
            {
                var result = await ldapService.DisableUserAsync(u.UserPrincipalName);
                if (!result.Success)
                    throw new Exception(result.Message);
            }, false);

            RunTest("EnableAndUnlockUser", async () =>
            {
                var result = await ldapService.EnableUserAsync(u.UserPrincipalName);
                if (!result.Success)
                    throw new Exception(result.Message);
            }, false);

            //RunTest("UpsertUser (Add)", async () =>
            //{
            //    Console.WriteLine("New User Password??");
            //    string? newPassword = Console.ReadLine();

            //    var result = await ldapService.UpsertUserAsync(
            //        upn: t.Upn,
            //        setPassword: newPassword,
            //        email: t.Email,
            //        displayName: t.DisplayName,
            //        company: t.Company,
            //        jobTitle: t.JobTitle,
            //        mobile: t.Telephone,
            //        department: t.Department,
            //        office: "IBKS - LA",
            //        managerDn: "",
            //        street: "IBKS",
            //        city: "Los Angeles",
            //        zip: "90066");

            //    if (!result.Success)
            //        throw new Exception(result.Message);

            //    Console.WriteLine("Add Result: " + result.Message);
            //}, false);

            //RunTest("UpsertUser (Mod)", async () =>
            //{
            //    string tStamp = DateTime.Now.ToString("HHmmss");
            //    Console.WriteLine("Mod Stamp = " + tStamp);

            //    var result = await ldapService.UpsertUserAsync(
            //        upn: u.UserPrincipalName,
            //        setPassword: "",
            //        email: u.Mail,
            //        displayName: u.DisplayName + tStamp,
            //        company: u.Company + tStamp,
            //        jobTitle: u.JobTitle + tStamp,
            //        mobile: u.MobilePhone + tStamp,
            //        department: u.Department + tStamp,
            //        street: u.Street + tStamp,
            //        city: u.City + tStamp,
            //        zip: u.ZipPostalCode + tStamp,
            //        office: "IBKS - LA",
            //        managerDn: "");

            //    if (!result.Success)
            //        throw new Exception(result.Message);

            //    Console.WriteLine("Mod Result: " + result.Message);
            //}, false);

            RunTest("ResetPassword", async () =>
            {
                Console.WriteLine($"[ Reset Password for {u.DistinguishedName}? ]");
                string? resetPassword = Console.ReadLine();

                if (resetPassword?.Length > 0)
                {
                    var result = await ldapService.ResetPasswordAsync(u.UserPrincipalName, resetPassword.Trim());
                    if (!result.Success)
                        throw new Exception(result.Message);

                    Console.WriteLine("Password Reset: " + result.Message);
                }
            });

            RunTest("Add GRoup", async () =>
            {
                Console.WriteLine($"Add to - Group Id?? ");
                int agrpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
                LdapGroup ag = ldapGroups[agrpId - 1];

                if (agrpId > 0)
                {
                    var result = await ldapService.AddToGroupAsync(u.UserPrincipalName, ag.AzureOrObjectID.ToString());
                    if (!result.Success)
                        throw new Exception(result.Message);

                    Console.WriteLine("Added Result: " + result.Message);
                }
            });


            RunTest("Remove Group", async () =>
            {
                Console.WriteLine($"Remove - Group Id?? ");
                int agrpId = Convert.ToInt32(Console.ReadLine() ?? string.Empty);
                LdapGroup ag = ldapGroups[agrpId - 1];

                if (agrpId > 0)
                {
                    var result = await ldapService.RemoveGroupAsync(u.UserPrincipalName, ag.AzureOrObjectID.ToString());
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

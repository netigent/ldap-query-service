using Netigent.Utils.Ldap;
using Netigent.Utils.Ldap.Models;

namespace Netigent.Utils.LdapTests
{
    public class AzureADTests
    {
#pragma warning disable NUnit1032 // An IDisposable field/property should be Disposed in a TearDown method
        private ILdapQueryService _service;
#pragma warning restore NUnit1032 // An IDisposable field/property should be Disposed in a TearDown method

        [SetUp]
        public void Setup()
        {
            _service = new LdapQueryService(
                serverDns: "corp.NETIGENT.co",
                searchBase: "OU=AADDC Users,DC=NETIGENT,DC=co",
                port: 636,
                useSSL: false,
                defaultUserDomain: "NETIGENT",
                maxTries: 2,
                retryDelayMs: 300,
                serviceAccount: "NETIGENT\\the.developer",
                serviceKey: "");
        }

        [TearDown]
        public void Disposing()
        {
            _service = null;
        }

        [TestCase("ldap.test", "")]
        [TestCase("NETIGENT\\ldap.test", "")]
        [TestCase("ldap.test@NETIGENT.co", "")]
        [TestCase("ldap.test@yahoo.com", "")]
        public void UserLogin_ValidCredentials_ReturnsSuccess(string username, string password)
        {
            LdapResult<LdapUser> result = _service.UserLogin(username, password);

            // Assert
            Assert.IsTrue(result.Success, message: result.Message);
        }

        [TestCase("ldap.test", "")]
        [TestCase("NETIGENT\\ldap.test", "")]
        [TestCase("ldap.test@NETIGENT.co", "")]
        [TestCase("ldap.test@yahoo.com", "")]
        public async Task UserModify_ReturnsSuccessAsync(string username, string password)
        {
            LdapResult result = await _service.UpsertUserAsync(username, password, "ldap.test@hotmai.com", "From Unit");

            // Assert
            Assert.IsTrue(result.Success, message: result.Message);
        }

        [TestCase("the.developer", "", "", "")]
        public async Task UpsertUser_Creds_ReturnsFalseAsync(string username, string password, string email, string displayname)
        {
            LdapResult result = await _service.UpsertUserAsync(username, password, email, displayname);

            // Assert
            Assert.IsTrue(result.Success);
        }

        [Test]
        public void GetUsers_ReturnsUserList()
        {
            IList<LdapUser>? result = _service.GetUsers();

            // Assert
            Assert.That(result?.Count > 0);
        }

        [TestCase("the.developer")]
        public void GetUser_ValidUserQuery_ReturnsUser(string query)
        {
            var result = _service.GetUser(query);

            // Assert
            Assert.That(result != null);
        }

        [Test]
        public void GetGroups_ReturnsGroupList()
        {
            IList<LdapGroup>? result = _service.GetGroups();

            // Assert
            Assert.That(result?.Count > 0);
        }



        [TestCase("the.developer", "", ExpectedResult = false)]
        public async Task<bool> ResetPassword_ValidUser_ReturnsSuccessAsync(string username, string password)
        {
            LdapResult result = await _service.ResetPasswordAsync(username, password);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }

        [TestCase("the.developer", ExpectedResult = true)]
        public async Task<bool> DisableUser_ValidUsername_ReturnsSuccessAsync(string username)
        {
            LdapResult result = await _service.DisableUserAsync(username);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }

        [TestCase("the.developer", ExpectedResult = true)]
        public async Task<bool> EnableAndUnlockUser_ValidUsername_ReturnsSuccessAsync(string username)
        {
            LdapResult result = await _service.EnableUserAsync(username);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }
    }
}
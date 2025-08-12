using Netigent.Utils.Ldap;
using Netigent.Utils.Ldap.Enum;
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
        public void UserModify_ReturnsSuccess(string username, string password)
        {
            LdapResult result = _service.UpsertUser(username, password, "ldap.test@hotmai.com", "From Unit");

            // Assert
            Assert.IsTrue(result.Success, message: result.Message);
        }

        [TestCase("the.developer", "", "", "")]
        public void UpsertUser_Creds_ReturnsFalse(string username, string password, string email, string displayname)
        {
            LdapResult result = _service.UpsertUser(username, password, email, displayname);

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

        [TestCase(LdapQueryAttribute.SamAccountName, "the.developer")]
        public void GetUser_ValidUserQuery_ReturnsUser(LdapQueryAttribute queryAttribute, string query)
        {
            LdapUser? result = _service.GetUser(queryAttribute, query);

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
        public bool ResetPassword_ValidUser_ReturnsSuccess(string username, string password)
        {
            LdapResult result = _service.ResetPassword(username, password);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }

        [TestCase("the.developer", ExpectedResult = true)]
        public bool DisableUser_ValidUsername_ReturnsSuccess(string username)
        {
            LdapResult result = _service.DisableUser(username);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }

        [TestCase("the.developer", ExpectedResult = true)]
        public bool EnableAndUnlockUser_ValidUsername_ReturnsSuccess(string username)
        {
            LdapResult result = _service.EnableAndUnlockUser(username);

            // Assert
            Assert.IsTrue(result.Success);
            return result.Success;
        }
    }
}
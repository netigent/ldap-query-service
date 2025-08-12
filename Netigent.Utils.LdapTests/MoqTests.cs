using Moq;
using Netigent.Utils.Ldap;
using Netigent.Utils.Ldap.Enum;
using Netigent.Utils.Ldap.Models;

namespace Netigent.Utils.LdapTests
{
    public class MoqTests
    {
        private Mock<ILdapQueryService> _ldapQueryServiceMock;

        [SetUp]
        public void Setup()
        {
            _ldapQueryServiceMock = new Mock<ILdapQueryService>();
        }

        [TearDown]
        public void Disposing()
        {
        }

        [TestCase("the.developer", "")]
        [TestCase("NETIGENT\\the.developer", "")]
        [TestCase("the.developer@NETIGENT.co", "")]
        public void UserLogin_ValidCredentials_ReturnsSuccess(string username, string password)
        {
            var expectedResult = new LdapResult<LdapUser> { Success = true };

            _ldapQueryServiceMock
                .Setup(x => x.UserLogin(username, password, It.IsAny<string>()))
                .Returns(expectedResult);

            // Act
            var result = _ldapQueryServiceMock.Object.UserLogin(username, password);

            // Assert
            Assert.IsTrue(result.Success);

            _ldapQueryServiceMock.Verify(x => x.UserLogin(username, password, It.IsAny<string>()), Times.Once);
        }

        [Test]
        public void GetUsers_ReturnsUserList()
        {
            // Arrange
            var expectedUsers = new List<LdapUser>
            {
                new LdapUser { SamAccountName = "the.developer" },
                new LdapUser { SamAccountName = "the.developer" }
            };

            _ldapQueryServiceMock
                .Setup(x => x.GetUsers())
                .Returns(expectedUsers);

            // Act
            var users = _ldapQueryServiceMock.Object.GetUsers();

            // Assert
            Assert.AreEqual(2, users.Count);
            Assert.AreEqual("the.developer", users[0].SamAccountName);
        }

        [Test]
        public void GetUser_ValidUserQuery_ReturnsUser()
        {
            // Arrange
            var expectedUser = new LdapUser { SamAccountName = "the.developer" };

            _ldapQueryServiceMock
                .Setup(x => x.GetUser(LdapQueryAttribute.SamAccountName, "the.developer"))
                .Returns(expectedUser);

            // Act
            var user = _ldapQueryServiceMock.Object.GetUser(LdapQueryAttribute.SamAccountName, "the.developer");

            // Assert
            Assert.AreEqual("the.developer", user.SamAccountName);
        }

        [Test]
        public void GetGroups_ReturnsGroupList()
        {
            // Arrange
            var expectedGroups = new List<LdapGroup>
            {
                new LdapGroup { SamAccountName = "Admin" },
                new LdapGroup { SamAccountName = "Users" }
            };

            _ldapQueryServiceMock
                .Setup(x => x.GetGroups())
                .Returns(expectedGroups);

            // Act
            var groups = _ldapQueryServiceMock.Object.GetGroups();

            // Assert
            Assert.AreEqual(2, groups.Count);
            Assert.AreEqual("Admin", groups[0].SamAccountName);
        }

        [Test]
        public void GetGroup_ValidGroupQuery_ReturnsGroup()
        {
            // Arrange
            var expectedGroup = new LdapGroup { SamAccountName = "Admin" };

            _ldapQueryServiceMock
                .Setup(x => x.GetGroup("Admin", LdapQueryAttribute.DisplayName))
                .Returns(expectedGroup);

            // Act
            var group = _ldapQueryServiceMock.Object.GetGroup("Admin");

            // Assert
            Assert.AreEqual("Admin", group.SamAccountName);
        }

        [Test]
        public void MemberOf_ValidUserAndGroup_ReturnsTrue()
        {
            // Arrange
            _ldapQueryServiceMock
                .Setup(x => x.IsMemberOf("the.developer", "Admin", LdapQueryAttribute.DisplayName))
                .Returns(true);

            // Act
            var isMember = _ldapQueryServiceMock.Object.IsMemberOf("the.developer", "Admin", LdapQueryAttribute.DisplayName);

            // Assert
            Assert.IsTrue(isMember);
        }

        [Test]
        public void ResetPassword_ValidUser_ReturnsSuccess()
        {
            // Arrange
            var username = "the.developer";
            var newPassword = "newPassword";
            var expectedResult = new LdapResult { Success = true };

            _ldapQueryServiceMock
                .Setup(x => x.ResetPassword(username, newPassword))
                .Returns(expectedResult);

            // Act
            var result = _ldapQueryServiceMock.Object.ResetPassword(username, newPassword);

            // Assert
            Assert.IsTrue(result.Success);
        }

        [Test]
        public void RunSearchQuery_ValidFilter_ReturnsResults()
        {
            // Arrange
            var expectedResults = new List<LdapGeneric>
    {
        new LdapGeneric { DistinguishedName = "cn=John Doe,dc=example,dc=com" },
        new LdapGeneric { DistinguishedName = "cn=Jane Doe,dc=example,dc=com" }
    };

            _ldapQueryServiceMock
                .Setup(x => x.RunSearchQuery("(objectClass=user)"))
                .Returns(expectedResults);

            // Act
            var results = _ldapQueryServiceMock.Object.RunSearchQuery("(objectClass=user)");

            // Assert
            Assert.AreEqual(2, results.Count);
        }

        [Test]
        public void DisableUser_ValidUsername_ReturnsSuccess()
        {
            // Arrange
            var username = "the.developer";
            var expectedResult = new LdapResult { Success = true };

            _ldapQueryServiceMock
                .Setup(x => x.DisableUser(username))
                .Returns(expectedResult);

            // Act
            var result = _ldapQueryServiceMock.Object.DisableUser(username);

            // Assert
            Assert.IsTrue(result.Success);
        }

        [Test]
        public void EnableAndUnlockUser_ValidUsername_ReturnsSuccess()
        {
            // Arrange
            var username = "the.developer";
            var expectedResult = new LdapResult { Success = true };

            _ldapQueryServiceMock
                .Setup(x => x.EnableAndUnlockUser(username))
                .Returns(expectedResult);

            // Act
            var result = _ldapQueryServiceMock.Object.EnableAndUnlockUser(username);

            // Assert
            Assert.IsTrue(result.Success);
        }
    }
}
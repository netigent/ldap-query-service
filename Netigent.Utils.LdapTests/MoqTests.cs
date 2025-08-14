using Moq;
using Netigent.Utils.Ldap;
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
        public void MemberOf_ValidUserAndGroup_ReturnsTrue()
        {
            // Arrange
            _ldapQueryServiceMock
                .Setup(x => x.IsMemberOf("the.developer", "Admin"))
                .Returns(true);

            // Act
            var isMember = _ldapQueryServiceMock.Object.IsMemberOf("the.developer", "Admin");

            // Assert
            Assert.IsTrue(isMember);
        }
    }
}
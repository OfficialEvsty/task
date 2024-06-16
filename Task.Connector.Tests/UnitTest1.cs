using Task.Integration.Data.DbCommon;
using Task.Integration.Data.Models;
using Task.Integration.Data.Models.Models;

namespace Task.Connector.Tests
{
    public class UnitTest1
    {
        static string requestRightGroupName = "Request";
        static string itRoleRightGroupName = "Role";
        static string delimeter = ":";
        static string mssqlConnectionString = "Server=127.0.0.1,1433;Database=connector_db;User Id=sa;Password=SuperDataBase32@;TrustServerCertificate=True;";
        static string postgreConnectionString = "Server=127.0.0.1;Port=5438;Database=connector_db;Username=admin;Password=connector_db_pass;";
        static Dictionary<string, string> connectorsCS = new Dictionary<string, string>
        {
            { "MSSQL",$"ConnectionString='{mssqlConnectionString}';Provider='SqlServer.2019';SchemaName='AvanpostIntegrationTestTaskSchema';"},
            { "POSTGRE", $"ConnectionString='{postgreConnectionString}';Provider='PostgreSQL.9.5';SchemaName='AvanpostIntegrationTestTaskSchema';"}
        };
        static Dictionary<string, string> dataBasesCS = new Dictionary<string, string>
        {
            { "MSSQL",mssqlConnectionString},
            { "POSTGRE", postgreConnectionString}
        };

        public DataManager Init(string providerName)
        {
            var factory = new DbContextFactory(dataBasesCS[providerName]);
            var dataSetter = new DataManager(factory, providerName);
            dataSetter.PrepareDbForTest();
            return dataSetter;
        }

        public IConnector GetConnector(string provider)
        {
            IConnector connector = new ConnectorDb();
            connector.StartUp(connectorsCS[provider]);
            connector.Logger = new FileLogger($"{DateTime.Now.ToString("yyyyMMdd_HHmmss")}connector{provider}.Log", $"{DateTime.Now.ToString("yyyyMMdd_HHmmss")}connector{provider}");
            return connector;
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void CreateUser(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            connector.CreateUser(new UserToCreate("testUserToCreate", "testPassword") { Properties = new UserProperty[] { new UserProperty("isLead", "false") } });
            Assert.NotNull(dataSetter.GetUser("testUserToCreate"));
            Assert.Equal(DefaultData.MasterUserDefaultPassword, dataSetter.GetUserPassword(DefaultData.MasterUserLogin));
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void GetAllProperties(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var propInfos = connector.GetAllProperties();
            Assert.Equal(DefaultData.PropsCount+1/*password too*/, propInfos.Count());
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void GetUserProperties(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var userInfo = connector.GetUserProperties(DefaultData.MasterUserLogin);
            Assert.NotNull(userInfo);
            Assert.Equal(5, userInfo.Count());
            Assert.True(userInfo.FirstOrDefault(_ => _.Value.Equals(DefaultData.MasterUser.TelephoneNumber)) != null);
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void IsUserExists(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            Assert.True(connector.IsUserExists(DefaultData.MasterUserLogin));
            Assert.False(connector.IsUserExists(TestData.NotExistingUserLogin));
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void UpdateUserProperties(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var userInfo = connector.GetUserProperties(DefaultData.MasterUserLogin);
            var propertyName = connector.GetUserProperties(DefaultData.MasterUserLogin).First(_ => _.Value.Equals(DefaultData.MasterUser.TelephoneNumber)).Name;
            var propsToUpdate = new UserProperty[]
            {
                new UserProperty(propertyName,TestData.NewPhoneValueForMasterUser)
            };
            connector.UpdateUserProperties(propsToUpdate, DefaultData.MasterUserLogin);
            Assert.Equal(TestData.NewPhoneValueForMasterUser, dataSetter.GetUser(DefaultData.MasterUserLogin).TelephoneNumber);
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void GetAllPermissions(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var permissions = connector.GetAllPermissions();
            Assert.NotNull(permissions);
            Assert.Equal(DefaultData.RequestRights.Length + DefaultData.ITRoles.Length, permissions.Count());
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void AddUserPermissions(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var RoleId = $"{itRoleRightGroupName}{delimeter}{dataSetter.GetITRoleId()}";
            connector.AddUserPermissions(
                DefaultData.MasterUserLogin,
                new [] { RoleId });
            Assert.True(dataSetter.MasterUserHasITRole(dataSetter.GetITRoleId().ToString()));
            Assert.True(dataSetter.MasterUserHasRequestRight(dataSetter.GetRequestRightId(DefaultData.RequestRights[DefaultData.MasterUserRequestRights.First()].Name).ToString()));
        }

        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void RemoveUserPermissions(string provider)
        {
            var dataSetter = Init(provider);
            var connector = GetConnector(provider);
            var requestRightIdToDrop = $"{requestRightGroupName}{delimeter}{dataSetter.GetRequestRightId(DefaultData.RequestRights[DefaultData.MasterUserRequestRights.First()].Name)}";
            connector.RemoveUserPermissions(
                DefaultData.MasterUserLogin,
                new [] { requestRightIdToDrop });
            Assert.False(dataSetter.MasterUserHasITRole(dataSetter.GetITRoleId().ToString()));
            Assert.False(dataSetter.MasterUserHasRequestRight(dataSetter.GetRequestRightId(DefaultData.RequestRights[DefaultData.MasterUserRequestRights.First()].Name).ToString()));
        }
        [Theory]
        [InlineData("MSSQL")]
        [InlineData("POSTGRE")]
        public void GetUserPermissions(string provider)
        {
            Init(provider);
            var connector = GetConnector(provider);
            var permissions = connector.GetUserPermissions(DefaultData.MasterUserLogin);
            Assert.Equal(DefaultData.MasterUserRequestRights.Length, permissions.Count());
        }
    }
}
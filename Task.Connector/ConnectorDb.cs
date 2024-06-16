using Task.Integration.Data.DbCommon.DbModels;
using Task.Integration.Data.Models.Models;
using Task.Integration.Data.DbCommon;
using Task.Integration.Data.Models;
using System.Reflection;


namespace Task.Connector
{
    public class ConnectorDb : IConnector
    {
        private DataContext? m_context;

        /// <summary>
        /// Конструктор пуст - обязательное требование
        /// </summary>
        public ConnectorDb() { }
        public void StartUp(string connectionString)
        {
            /// <summary>
            /// Метод, позволяющий разбить строку соединения на словарь имя_параметра:значение_параметра
            /// </summary>
            Dictionary<string, string> ParseConnectionString(string connectionString)
            {
                List<string> SplitParameters(string connectionString)
                {
                    void AddSubstring(string source, List<string> result, int start, int end)
                    {
                        var substring = source.Substring(start, end - start).Trim();
                        if (!string.IsNullOrEmpty(substring))
                        {
                            result.Add(substring);
                        }
                    }

                    var result = new List<string>();
                    bool inQuotes = false;
                    int startIndex = 0;

                    for (int i = 0; i < connectionString.Length; i++)
                    {
                        if (connectionString[i] == '\'')
                        {
                            inQuotes = !inQuotes;
                        }
                        else if (connectionString[i] == ';' && !inQuotes)
                        {
                            AddSubstring(connectionString, result, startIndex, i);
                            startIndex = i + 1;
                        }
                    }
                    if (startIndex < connectionString.Length)
                    {
                        AddSubstring(connectionString, result, startIndex, connectionString.Length);
                    }

                    return result;
                }
                var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var parameters = SplitParameters(connectionString);

                foreach(var param in parameters)
                {
                    var keyVal = param.Split("=", 2);
                    if (keyVal.Length == 2)
                        config[keyVal[0].Trim()] = keyVal[1].Trim('\'');
                }
                return config;
            }
            // Разбитие строки соединения в словарь параметров
            var config = ParseConnectionString(connectionString);
            string provider;
            switch (config["Provider"].ToLower())
            {
                case "postgresql.9.5":
                    provider = "POSTGRE";                    
                    break;
                case "sqlserver.2019":
                    provider = "MSSQL";
                    break;
                default:
                    throw new NotSupportedException($"Provider {config["Provider"]} is not supported.");                
            }
            var contextFactory = new DbContextFactory(config["ConnectionString"]);
            m_context = contextFactory.GetContext(provider);

            Logger?.Debug($"Connection to {config["Provider"]} database successfully established.");
        }

        public void CreateUser(UserToCreate user)
        {
            if (IsUserExists(user.Login))
            {
                Logger?.Warn($"User with same login-'{user.Login}' already exists in Users Table.");
                return;
            }

            string GetPropertyOrDefault(string propertyName, string defaultValue) =>
                user.Properties.FirstOrDefault(p => p.Name == propertyName)?.Value ?? defaultValue;

            var userModel = new User
            {
                Login = user.Login,
                FirstName = GetPropertyOrDefault("firstName", "firstName"),
                MiddleName = GetPropertyOrDefault("middleName", "middleName"),
                LastName = GetPropertyOrDefault("lastName", "lastName"),
                TelephoneNumber = GetPropertyOrDefault("telephoneNumber", "telephoneNumber"),
                IsLead = user.Properties.FirstOrDefault(p => p.Name == "isLead")?.Value == "true"
            };

            if (m_context != null)
            {
                m_context.Users.Add(userModel);
                m_context.Passwords.Add(new Sequrity { Password = user.HashPassword, UserId = user.Login });
                m_context.SaveChanges();
            }

            Logger?.Debug($"User with login-'{user.Login}' successfully added in Users Table.");
            Logger?.Debug($"Password for user-'{user.Login}' saved.");
        }

        public IEnumerable<Property> GetAllProperties()
        {
            var userProps = typeof(User).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                                        .Append(m_context.Passwords.GetType().GetGenericArguments()[0].GetProperty("Password"));
            return userProps.Where(up => up.Name != "Login").Select(up => new Property(up.Name, "User Properties extends with password"));
        }

        public IEnumerable<UserProperty> GetUserProperties(string userLogin)
        {
            try
            {
                if (!IsUserExists(userLogin))
                    throw new Exception($"User with login-'{userLogin}' doesn't exist in scope.");
                var user = m_context?.Users.First(u => u.Login == userLogin);
                return new List<UserProperty> { 
                    new UserProperty(nameof(user.FirstName), user.FirstName),
                    new UserProperty(nameof(user.MiddleName), user.MiddleName),
                    new UserProperty(nameof(user.LastName), user.LastName),
                    new UserProperty(nameof(user.TelephoneNumber), user.TelephoneNumber),
                    new UserProperty(nameof(user.IsLead), user.IsLead.ToString())
                };
            }
            catch(Exception ex)
            {
                Logger?.Warn($"User doesn't exist in Users Table. Message:{ex.Message}");
                return Enumerable.Empty<UserProperty>();
            }
        }

        public bool IsUserExists(string userLogin)
        {
            if (m_context == null)
                throw new NullReferenceException("DbContext has nullreference");
            var user = m_context.Users.Where(x => x.Login == userLogin).FirstOrDefault();
            return user != null;
        }

        public void UpdateUserProperties(IEnumerable<UserProperty> properties, string userLogin)
        {
            if (m_context == null)
            {
                Logger?.Error("DbContext object is null.");
                return;
            }

            var userToUpdate = m_context.Users.FirstOrDefault(u => u.Login == userLogin);
            if (userToUpdate == null)
            {
                Logger?.Warn($"User with login '{userLogin}' not found.");
                return;
            }

            var userProps = typeof(User).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                                        .ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);

            foreach (var property in properties)
            {
                if (userProps.TryGetValue(property.Name, out var propInfo) && propInfo.CanWrite)
                {
                    var convertedValue = Convert.ChangeType(property.Value, propInfo.PropertyType);
                    propInfo.SetValue(userToUpdate, convertedValue);
                }
                else
                {
                    Logger?.Warn($"Property '{property.Name}' does not exist or is read-only.");
                }
            }

            m_context.SaveChanges();
        }

        public IEnumerable<Permission> GetAllPermissions()
        {
            var uid = 10001; 
            if (m_context == null)
            {
                Logger?.Error($"DbContext object nullreference.");
                return Enumerable.Empty<Permission>();
            }
            var permissions = m_context.ITRoles.Select(
                itr => new Permission(0.ToString(), itr.Name, itr.CorporatePhoneNumber)).ToList()
                .Concat(m_context.RequestRights
                .Select(rr => new Permission(0.ToString(), rr.Name, "from request rights table"))).ToList();
            permissions.ForEach(perm => perm.Id = uid++.ToString());
            return permissions;
        }

        public void AddUserPermissions(string userLogin, IEnumerable<string> rightIds)
        {
            const string Delimiter = ":";
            const string RequestGroupName = "Request";
            const string RoleGroupName = "Role";

            if (m_context == null)
            {
                Logger?.Error($"DbContext object nullreference.");
                return;
            }
            if (!IsUserExists(userLogin))
            {
                Logger?.Warn($"User with login-'{userLogin}' doesn't exist in scope.");
                return;
            }

            IEnumerable<(string Group, int Id)> SplitRightsByGroupName(IEnumerable<string[]> perms)
            {
                return perms.Select(p => (Group: p[0], Id: Convert.ToInt32(p[1])));
            }

            void AddPermissions(IEnumerable<(string Group, int Id)> permissions, string groupName, Func<int, bool> validateFunc, Func<int, bool> existsFunc, Action<IEnumerable<int>> addAction, string logGroupName)
            {
                var groupedPermissions = permissions.Where(p => p.Group == groupName);

                var validPermissions = groupedPermissions.Where(p => validateFunc(p.Id));
                var invalidPermissions = groupedPermissions.Except(validPermissions);

                Logger?.Warn($"These rights: {string.Join(",", invalidPermissions.Select(x => x.Id))} don't exist in the {logGroupName} Table.");

                var existingPermissions = validPermissions.Where(p => existsFunc(p.Id));
                Logger?.Debug($"These rights: {string.Join(",", existingPermissions.Select(x => x.Id))} are already applied to user with login-{userLogin}");

                var permissionsToAdd = validPermissions.Except(existingPermissions).Select(p => p.Id);
                addAction(permissionsToAdd);

                Logger?.Debug($"Rights: {string.Join(",", validPermissions.Select(x => x.Id))} successfully applied to user with login-{userLogin}");
            }

            IEnumerable<string[]> permissionsNameId = rightIds.Select(x => x.Split(Delimiter, 2));
            var permissions = SplitRightsByGroupName(permissionsNameId);

            AddPermissions(
                permissions,
                RequestGroupName,
                id => m_context.RequestRights.Any(rr => rr.Id == id),
                id => m_context.UserRequestRights.Any(urr => urr.UserId == userLogin && urr.RightId == id),
                ids => m_context.UserRequestRights.AddRange(ids.Select(id => new UserRequestRight { RightId = id, UserId = userLogin })),
                "RequestRights");

            AddPermissions(
                permissions,
                RoleGroupName,
                id => m_context.ITRoles.Any(role => role.Id == id),
                id => m_context.UserITRoles.Any(urole => urole.UserId == userLogin && urole.RoleId == id),
                ids => m_context.UserITRoles.AddRange(ids.Select(id => new UserITRole { RoleId = id, UserId = userLogin })),
                "UserITRoles");

            m_context.SaveChanges();
        }

        public void RemoveUserPermissions(string userLogin, IEnumerable<string> rightIds)
        {
            const string Delimiter = ":";
            const string RequestGroupName = "Request";
            const string RoleGroupName = "Role";

            if (m_context == null)
            {
                Logger?.Error($"DbContext object nullreference.");
                return;
            }
            if (!IsUserExists(userLogin))
            {
                Logger?.Warn($"User with login-'{userLogin}' doesn't exist in scope.");
                return;
            }

            IEnumerable<(string Group, int Id)> SplitRightsByGroupName(IEnumerable<string[]> perms)
            {
                return perms.Select(p => (Group: p[0], Id: Convert.ToInt32(p[1])));
            }

            void RemovePermissions(IEnumerable<(string Group, int Id)> permissions, string groupName, Func<int, bool> existsFunc, Action<IEnumerable<int>> removeAction)
            {
                var groupedPermissions = permissions.Where(p => p.Group == groupName);
                
                var userPermissionsToDelete = groupedPermissions.Where(p => existsFunc(p.Id));
                removeAction(userPermissionsToDelete.Select(uptd => uptd.Id));
                Logger?.Debug($"Rights: {string.Join(",", userPermissionsToDelete.Select(x => x.Id))} successfully deleted from user with login-{userLogin}");
            }

            IEnumerable<string[]> permissionsNameId = rightIds.Select(x => x.Split(Delimiter, 2));
            var permissions = SplitRightsByGroupName(permissionsNameId);

            RemovePermissions(permissions,
                RoleGroupName,
                id => m_context.UserITRoles.Any(uitr => uitr.UserId == userLogin && uitr.RoleId == id),
                ids => m_context.UserITRoles.RemoveRange(m_context.UserITRoles.Where(uitr => ids.Any(id => uitr.RoleId == id)))
                );

            RemovePermissions(permissions,
                RequestGroupName,
                id => m_context.UserRequestRights.Any(urr => urr.UserId == userLogin && urr.RightId == id),
                ids => m_context.UserRequestRights.RemoveRange(m_context.UserRequestRights.Where(urr => ids.Any(id => urr.RightId == id)))
                );

            m_context.SaveChanges();
        }

        public IEnumerable<string> GetUserPermissions(string userLogin)
        {
            if (!IsUserExists(userLogin))
            {
                Logger?.Warn($"User with login-'{userLogin}' doesn't exist in scope.");
                return Enumerable.Empty<string>();
            }

            var userRoles = m_context.UserITRoles
                .Where(urole => urole.UserId == userLogin)
                .Join(m_context.ITRoles, urole => urole.RoleId, role => role.Id, (urole, role) => role.Name)
                .ToList();

            var userRights = m_context.UserRequestRights
                .Where(uright => uright.UserId == userLogin)
                .Join(m_context.RequestRights, uright => uright.RightId, right => right.Id, (uright, right) => right.Name)
                .ToList();

            return userRoles.Concat(userRights);
        }
        
        public ILogger? Logger { get; set; }
    }
}
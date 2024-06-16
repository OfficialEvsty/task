### Результаты проведенных тестов
![Результаты проведенных тестов](https://cdn.discordapp.com/attachments/1060654257365319700/1251706304691437619/tests.png?ex=666f8dd6&is=666e3c56&hm=99d7aeb233189cce3a5f266c7b5462cdd858ff95dac69ed9583bdbf942abeb3d&) 







# Цель задачи
* Написать библиотеку для интеграции продукта с системой клиента.

## Замечания по выполнению задачи
* Можно, но не нужно смотреть pull request'ы c примерами выполнениями задачи всеми кандидатами, потому что Pull request'ы не содержат ни одного решения задачи, которе выполняет все требования постановки
* Копирование решения задачи из pull request обнуляет всю работу, потому что копируются и типовые ошибки. Такие работы не просматриваются полностью, собеседование с кандидатом не проводится.
* Задача решается с целью оценки навыков писать код, даже если он будет работать где-то неправильно или не так понят.

### Описание взаимодействия продукта с системой клиента
* Продукт подгружает библиотеку во время работы и с её помощью работает с необходимой системой.
* Продукт использует методы чтения, которые определены в интерфейсе для создания целевой картины.
* Продукт использует методы изменения для управления целевой картиной на основании имеющейся целевой картины.

### Описание системы клиента
Система представляет собой сервис для технического обслуживания.
Внутри сервиса существуют пользователи(User), имеющие свойства(Properties) и права(RequestRight и ItRole).
Свойства пользователя(его атрибуты) имеют постоянный состав(lastName, firstName, middleName, telephoneNumber, isLead). Стоит отметить, что Логин является уникальным идентификатором пользователя в системе и свойством не является!
Права(RequestRight и ItRole) позволяют пользователю выполнять те или иные операции в системе(например просмотривать необходимые для пользователя отчеты)
Список актуальных прав будет находится в соотвутствующих таблицах после развертывания/заполнения бд через утилиту Task.Integration.Data.DbCreationUtility, которая будет описана ниже.
Инициализация конфигурации конектора происходит через метод StartUp и обязательное требование - наличие пустого конструктора.

# Таблицы БД:
* Таблица с пользователями User(все столбцы ненулевые);
* Таблица с паролями Passwords(все столбцы ненулевые);
* Таблица с правами по изменению заявок RequestRight;
* Таблица с ролями исполнителей ItRole;
* Таблицы для связи пользователей и прав UserItRole, UserRequestRight(Все столбцы ненулевые, изменение прав пользователя состоит в добавлении и удалении данных из этих таблиц);

# Развертывание системы
Для создание схемы, таблиц и заполнения данными используется утилита Task.Integration.Data.DbCreationUtility.exe(папка DbCreationUtility). Поддерживаются MSSQL и Postgre. Поддерживаемые значения параметра -p POSTGRE, MSSQL.

#### Команды:
Task.Integration.Data.DbCreationUtility.exe -s "строка подключения к бд" -p "провайдер бд"

пример: Task.Integration.Data.DbCreationUtility.exe -s "Server=127.0.0.1;Port=5432;Database=testDb;Username=testUser;Password=12345678;" -p "POSTGRE"

# Структура решения:
* Task.Connector.Tests - проект с тестами коннектора(его можно и нужно использовать как точку входа в методы при отладке коннектора);
* Task.Connector - проект с реализуемым коннектором

# Задание
* Развернуть бд (Postgres или MSSQL) в Docker или с помощью других средств;
* Заполнить тестовыми данными с помощью утилиты Avanpost.Integration.DbCreationUtility;
* Реализовать интерфейс коннектора:
```csharp
        public ILogger Logger { get; set; }
        void StartUp(string connectionString); //Конфигурация коннектора через строку подключения (настройки для подключения к ресурсу(строка подключения к бд, 
        // путь к хосту с логином и паролем, дополнительные параметры конфигурации бизнес-логики и тд, формат любой, например: "key1=value1;key2=value2...";
        
		void CreateUser(UserToCreate user); // Создать пользователя с набором свойств по умолчанию.
		bool IsUserExists(string userLogin); // Проверка существования пользователя
        
		IEnumerable<Property> GetAllProperties(); // Метод позволяет получить все свойства пользователя(смотри Описание системы), пароль тоже считать свойством
        IEnumerable<UserProperty> GetUserProperties(string userLogin); // Получить все значения свойств пользователя
        void UpdateUserProperties(IEnumerable<UserProperty> properties, string userLogin);// Метод позволяет устанавливать значения свойств пользователя
        
		IEnumerable<Permission> GetAllPermissions();// Получить все права в системе (смотри Описание системы клиента)
        void AddUserPermissions(string userLogin, IEnumerable<string> rightIds);// Добавить права пользователю в системе
        void RemoveUserPermissions(string userLogin, IEnumerable<string> rightIds);// Удалить права пользователю в системе
        IEnumerable<string> GetUserPermissions(string userLogin);// Получить права пользователя в системе
```

# Требования по реализации интерфейса коннектора
* Коннектор реализует интерфейс IConnector (все методы интерфейса);
* Коннектор проходит все тесты
* Коннектор не изменяет данные в таблицах RequestRights и ItRole;
* Коннектор использует логирование через свойство Logger;
* При работе с Permission разделяет ItRole и RequestRight, то есть коннектор всегда понимает с каким Permission работает, а продукт просто использует права, прочитанные коннектором;


using Dapper;
using HowlDev.Web.Authentication.AccountAuth.Interfaces;
using HowlDev.Web.Authentication.Middleware;
using HowlDev.Web.Helpers.DbConnector;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// Service implementation to handle the database. Runs through Dapper.
/// <br/>
/// Requires a valid connection string to a Postgres database through the following key: 
/// <code>ConnectionStrings__PostgresConnection</code>
/// If you have an appsettings.json file, it would look like this:
/// <code>
/// "ConnectionStrings": {
///   "PostgresConnection": "Host=localhost;Database=accountAuth;Username=cody;Password=123456abc;"
/// }
/// </code>
/// </summary>
public partial class AuthService(IConfiguration config, ILogger<AuthService> logger) : IAuthService, IAuthMiddlewareService {
    private ConcurrentDictionary<string, Guid> guidLookup = new();
    private ConcurrentDictionary<string, int> roleLookup = new();
    private DbConnector conn = new DbConnector(config);

    #region User Creation/Validation
    /// <inheritdoc />
    public Task AddUserAsync(string accountName, string defaultPassword = "password", int defaultRole = 0) =>
        conn.WithConnectionAsync(async conn => {
            string passHash = Argon2Helper.HashPassword(defaultPassword);
            Guid guid = Guid.NewGuid();
            var AddUser = "insert into \"HowlDev.User\" values (@guid, @accountName, @passHash, @defaultRole)";
            try {
                await conn.ExecuteAsync(AddUser, new { guid, accountName, passHash, defaultRole });
            } catch (Exception e) {
                logger.LogError("AddUserAsync threw an error: {e}", e);
                throw new ArgumentException("Account name already exists.");
            }
        }
    );

    /// <inheritdoc />
    public Task<string> NewSignInAsync(string accountName) =>
        conn.WithConnectionAsync(async conn => {
            string newApiKey = StringHelper.GenerateRandomString(20);
            DateTime now = DateTime.Now;

            var addValidation = "insert into \"HowlDev.Key\" (accountId, apiKey, validatedOn) values (@accountName, @newApiKey, @now)";
            await conn.ExecuteAsync(addValidation, new { accountName, newApiKey, now });

            return newApiKey;
        }
    );

    /// <inheritdoc />
    public Task<IEnumerable<Account>> GetAllUsersAsync() =>
        conn.WithConnectionAsync(async conn => {
            var GetUsers = "select p.id, p.accountName, p.role from \"HowlDev.User\" p order by 1";
            try {
                return await conn.QueryAsync<Account>(GetUsers);
            } catch {
                return [];
            }
        }
    );

    /// <inheritdoc />
    public Task<Account> GetUserAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            return new Account {
                Id = await GetGuidAsync(account),
                AccountName = account,
                Role = await GetRoleAsync(account)
            };
        }
    );
    #endregion

    #region Validation
    /// <inheritdoc />
    public Task<DateTime> GetValidatedOnForKeyAsync(string accountName, string key) =>
        conn.WithConnectionAsync(async conn => {
            var validKey = "select k.validatedon from \"HowlDev.Key\" k where accountId = @accountName and apiKey = @key";
            return await conn.QuerySingleAsync<DateTime>(validKey, new { accountName, key });
        }
    );

    /// <inheritdoc />
    public Task<bool> IsValidUserPassAsync(string accountName, string password) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered IsValidUserPassAsync.");
            try {
                var pass = "select p.passHash from \"HowlDev.User\" p where accountName = @accountName";
                string storedPassword = await conn.QuerySingleAsync<string>(pass, new { accountName });
                return Argon2Helper.VerifyPassword(storedPassword, password);
            } catch (Exception e) {
                logger.LogWarning("Error: {a}", e);
                return false;
            }
        }
    );

    /// <inheritdoc />
    public Task ReValidateAsync(string accountId, string key) =>
        conn.WithConnectionAsync(async conn => {
            string time = DateTime.Now.ToUniversalTime().ToString("u");
            var validate = $"update \"HowlDev.Key\" hdk set validatedon = '{time}' where accountId = @accountId and apiKey = @key";
            await conn.ExecuteAsync(validate, new { accountId, key });
        }
    );
    #endregion

    #region Updates
    /// <inheritdoc />
    public Task UpdatePasswordAsync(string accountName, string newPassword) =>
        conn.WithConnectionAsync(async conn => {
            string newHash = Argon2Helper.HashPassword(newPassword);
            var pass = "update \"HowlDev.User\" p set passHash = @newHash where accountName = @accountName";
            await conn.ExecuteAsync(pass, new { accountName, newHash });
        }
    );

    /// <inheritdoc />
    public Task UpdateRoleAsync(string accountName, int newRole) =>
        conn.WithConnectionAsync(async conn => {
            var role = "update \"HowlDev.User\" p set role = @newRole where accountName = @accountName";
            await conn.ExecuteAsync(role, new { accountName, newRole });
            roleLookup[accountName] = newRole;
        }
    );
    #endregion

    #region Deletion/Sign Out
    /// <inheritdoc />
    public Task DeleteUserAsync(string accountId) =>
        conn.WithConnectionAsync(async conn => {
            await GlobalSignOutAsync(accountId);

            var removeUser = "delete from \"HowlDev.User\" where accountName = @accountId";
            await conn.ExecuteAsync(removeUser, new { accountId });
        }
    );

    /// <inheritdoc />
    public Task GlobalSignOutAsync(string accountId) =>
        conn.WithConnectionAsync(async conn => {
            var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
            await conn.ExecuteAsync(removeKeys, new { accountId });
        }
    );

    /// <inheritdoc />
    public Task KeySignOutAsync(string accountId, string key) =>
        conn.WithConnectionAsync(async conn => {
            var removeKey = "delete from \"HowlDev.Key\" where accountId = @accountId and apiKey = @key";
            await conn.ExecuteAsync(removeKey, new { accountId, key });
        }
    );

    /// <inheritdoc />
    public Task ExpiredKeySignOutAsync(TimeSpan length) =>
        conn.WithConnectionAsync(async conn => {
            DateTime expirationTime = DateTime.Now - length;
            var removeKey = "delete from \"HowlDev.Key\" where validatedOn < @expirationTime";
            await conn.ExecuteAsync(removeKey, new { expirationTime });
        }
    );
    #endregion

    #region Search
    /// <summary>
    /// Returns the Guid of a given account name. Has an internal dictionary to reduce 
    /// database calls and enable quick lookup.
    /// </summary>
    public Task<Guid> GetGuidAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetGuidAsync");
            if (guidLookup.TryGetValue(account, out Guid theirGuid)) {
                logger.LogDebug("GuidLookup contained key.");
                return theirGuid;
            } else {
                logger.LogDebug("GuidLookup did not contain the key.");
                string guid = "select id from \"HowlDev.User\" where accountName = @account";
                theirGuid = await conn.QuerySingleAsync<Guid>(guid, new { account });
                guidLookup.AddOrUpdate(account, theirGuid, (existingKey, existingValue) => theirGuid);
                return theirGuid;
            }
        }
    );

    /// <summary>
    /// Returns the Role of a given account name. Has an internal dictionary to reduce database calls
    /// and enable quick lookups. 
    /// </summary>
    public Task<int> GetRoleAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetRoleAsync");
            if (roleLookup.TryGetValue(account, out int theirRole)) {
                logger.LogDebug("RoleLookup contained key.");
                return theirRole;
            } else {
                logger.LogDebug("RoleLookup did not contain the key.");
                string role = "select role from \"HowlDev.User\" where accountName = @account";
                theirRole = await conn.QuerySingleAsync<int>(role, new { account });
                roleLookup.AddOrUpdate(account, theirRole, (existingKey, existingValue) => theirRole);
                return theirRole;
            }
        }
    );


    /// <inheritdoc />
    public Task<string> GetAccountNameAsync(Guid account) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """select accountName from "HowlDev.User" where id = @account""";
            return await conn.QuerySingleAsync<string>(sql, new { account });
        });

    #endregion

    /// <inheritdoc />
    public Task<int> GetCurrentSessionCountAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetCurrentSessionCountAsync");
            string connCount = "select count(*) from \"HowlDev.Key\" where accountId = @account";
            return await conn.QuerySingleAsync<int>(connCount, new { account });
        });

    #region Queries
    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersAsync(string query, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.accountName ilike @SearchPattern
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { SearchPattern = $"%{query}%", limit });
            } catch {
                return [];
            }
        });

    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersAboveRoleAsync(int role, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.role > @role
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { role, limit });
            } catch {
                return [];
            }
        });

    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersAboveOrAtRoleAsync(int role, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.role >= @role
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { role, limit });
            } catch {
                return [];
            }
        });

    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersAtRoleAsync(int role, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.role = @role
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { role, limit });
            } catch {
                return [];
            }
        });

    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersBelowOrAtRoleAsync(int role, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.role <= @role
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { role, limit });
            } catch {
                return [];
            }
        });

    /// <inheritdoc />
    public Task<IEnumerable<Account>> QueryUsersBelowRoleAsync(int role, int limit = 10) =>
        conn.WithConnectionAsync(async conn => {
            string sql = """
            select p.id, p.accountName, p.role from "HowlDev.User" p
                where p.role < @role
                limit @limit
            """;
            try {
                return await conn.QueryAsync<Account>(sql, new { role, limit });
            } catch {
                return [];
            }
        });
    #endregion
}

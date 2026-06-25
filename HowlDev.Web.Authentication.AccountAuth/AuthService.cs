using Dapper;
using HowlDev.Web.Authentication.AccountAuth.Interfaces;
using HowlDev.Web.Authentication.Middleware;
using HowlDev.Web.Helpers.DbConnector;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

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
public class AuthService(IConfiguration config, ILogger<AuthService> logger) : IAuthService, IAuthMiddlewareService {
    private DbConnector conn = new DbConnector(config);
    private static Argon2Options options = new();

    #region User Creation/Validation
    /// <inheritdoc />
    public Task AddUserAsync(string accountName, string defaultPassword = "password", int defaultRole = 0) =>
        conn.WithConnectionAsync(async conn => {
            if (await AccountExistsAsync(accountName)) {
                throw new ArgumentException("Account name already exists.");
            }

            string passHash = Argon2Helper.HashPassword(defaultPassword, options);
            Guid guid = Guid.NewGuid();
            await conn.ExecuteAsync("insert into \"HowlDev.User\" values (@guid, @accountName, @passHash, @defaultRole)",
                new { guid, accountName, passHash, defaultRole });
        }
    );

    /// <inheritdoc />
    public Task<string> NewSignInAsync(string accountName) =>
        conn.WithConnectionAsync(async conn => {
            string newApiKey = StringHelper.GenerateRandomString(20);
            DateTime now = DateTime.Now;

            await conn.ExecuteAsync(
                "insert into \"HowlDev.Key\" (accountId, apiKey, validatedOn) values (@accountName, @newApiKey, @now)",
                new { accountName, newApiKey, now });

            return newApiKey;
        }
    );

    /// <inheritdoc />
    public Task<IEnumerable<Account>> GetAllUsersAsync() =>
        conn.WithConnectionAsync(async conn =>
        await conn.QueryAsync<Account>("select p.id, p.accountName, p.role from \"HowlDev.User\" p order by 1")
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
            string newHash = Argon2Helper.HashPassword(newPassword, options);
            var pass = "update \"HowlDev.User\" p set passHash = @newHash where accountName = @accountName";
            await conn.ExecuteAsync(pass, new { accountName, newHash });
        }
    );

    /// <inheritdoc />
    public Task UpdateRoleAsync(string accountName, int newRole) =>
        conn.WithConnectionAsync(async conn => {
            var role = "update \"HowlDev.User\" p set role = @newRole where accountName = @accountName";
            await conn.ExecuteAsync(role, new { accountName, newRole });
        }
    );


    /// <inheritdoc />
    public Task UpdateAccountNameAsync(Guid account, string newName) =>
        conn.WithConnectionAsync(async conn => {
            if (await AccountExistsAsync(newName)) {
                throw new ArgumentException("Account name is already being used.");
            }

            if (!await AccountExistsAsync(account)) {
                throw new ArgumentException("Guid is not tied to a user.");
            }

            string oldAccount = await GetAccountNameAsync(account);

            await GlobalSignOutAsync(oldAccount);
            var accNameUpdate = "update \"HowlDev.User\" p set accountName = @newName where id = @account";
            await conn.ExecuteAsync(accNameUpdate, new { account, newName });
        });
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
    /// <inheritdoc/>
    public Task<Guid> GetGuidAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetGuidAsync");
            string guid = "select id from \"HowlDev.User\" where accountName = @account";
            Guid theirGuid = await conn.QuerySingleAsync<Guid>(guid, new { account });
            return theirGuid;
        }
    );

    /// <inheritdoc/>
    public Task<int> GetRoleAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetRoleAsync");
            string role = "select role from \"HowlDev.User\" where accountName = @account";
            int theirRole = await conn.QuerySingleAsync<int>(role, new { account });
            return theirRole;
        }
    );

    /// <inheritdoc/>
    public Task<bool> AccountExistsAsync(Guid account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered AccountExistsAsync (Guid)");
            string sql = "select exists (select * from \"HowlDev.User\" where id = @account)";
            return await conn.QuerySingleAsync<bool>(sql, new { account });
        });

    /// <inheritdoc/>
    public Task<bool> AccountExistsAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered AccountExistsAsync (Account name)");
            string sql = "select exists (select * from \"HowlDev.User\" where  accountName = @account)";
            return await conn.QuerySingleAsync<bool>(sql, new { account });
        });

    /// <inheritdoc />
    public Task<string> GetAccountNameAsync(Guid account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetAccountNameAsync");
            string sql = """select accountName from "HowlDev.User" where id = @account""";
            return await conn.QuerySingleAsync<string>(sql, new { account });
        });

    #endregion

    #region Queries
    /// <inheritdoc />
    public Task<int> GetCurrentSessionCountAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetCurrentSessionCountAsync");
            string connCount = "select count(*) from \"HowlDev.Key\" where accountId = @account";
            return await conn.QuerySingleAsync<int>(connCount, new { account });
        });

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

    /// <summary>
    /// Set the conditions for the hashing algorithm for your specific machine
    /// to be as resilient as needed for your program and for the machine you're running 
    /// it on.
    /// 
    /// This will be called every time you need to run a hash, which is only when a user 
    /// is created or when they're signing in (in other words, rather infrequently), so 
    /// choose some options that maximize the time the machine can spend making it secure.
    /// </summary>
    public static void UpdateArgonOptions(Argon2Options newOpts) =>
        options = newOpts;

    /// <summary>
    /// Use with the <see cref="UpdateArgonOptions"/> method to benchmark the options
    /// you provided in that method. It will pass in the string "lorem ipsum password" 
    /// and time with a stopwatch how long the hash took, returning the time in milliseconds
    /// which you can print to the screen.
    /// 
    /// You should try to maximize the memory usage and get it ideally above 0.5 seconds 
    /// (or 500 ms as this will return), close to 1 second is better.
    /// </summary>
    public static int BenchmarkArgonOptions() {
        Stopwatch watch = Stopwatch.StartNew();
        Argon2Helper.HashPassword("lorem ipsum password", options);
        watch.Stop();
        return (int)watch.ElapsedMilliseconds;
    }

    /// <inheritdoc/>
    public Task<Result<Account>> TryGetUserAsync(string account) {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public Task<Result<DateTime>> TryGetValidatedOnForKeyAsync(string accountName, string key) {
        throw new NotImplementedException();
    }
}

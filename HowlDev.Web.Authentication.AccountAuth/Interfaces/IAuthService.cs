using HowlDev.Web.Authentication.Middleware;

namespace HowlDev.Web.Authentication.AccountAuth.Interfaces;

/// <summary/>
public interface IAuthService : IAuthMiddlewareService {
    /// <summary>
    /// Adds a new user if one doesn't already exist and throws an error if they do. Should 
    /// only be used in the sign-up process.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    Task AddUserAsync(string accountName, string defaultPassword, int defaultRole);

    /// <summary>
    /// Adds a new line to the API key table.
    /// </summary>
    /// <returns>API key</returns>
    Task<string> NewSignInAsync(string accountName);

    /// <summary>
    /// <c>For Debug Only</c>, I wouldn't reccommend assigning this an endpoint. Returns all users sorted by 
    /// ID. Swallows errors and returns an empty list. 
    /// </summary>
    Task<IEnumerable<Account>> GetAllUsersAsync();

    /// <summary>
    /// Returns True if the username and password match what's stored in the database. This 
    /// handles errors thrown by invalid users and simply returns False.
    /// </summary>
    /// <returns>If the hashed password equals the stored hash</returns>
    Task<bool> IsValidUserPassAsync(string accountName, string password);

    /// <summary>
    /// Updates the user's password in the table. Does not affect any of the API keys currently
    /// entered. 
    /// </summary>
    Task UpdatePasswordAsync(string accountName, string newPassword);

    /// <summary>
    /// Updates the user's role in the table. Does not affect any current keys.
    /// Does update the lookup dictionary with the new role. 
    /// </summary>
    Task UpdateRoleAsync(string accountName, int newRole);

    /// <summary>
    /// Updates the user's name tied to the GUID. Removes all current keys through a global sign out
    /// and clears the lookup dictionary of the prior account name. <br/>
    /// Throws an ArgumentException if the new name is already in use.
    /// </summary>
    /// <exception cref="ArgumentException" />
    Task UpdateAccountNameAsync(Guid account, string newName);

    /// <summary>
    /// Deletes all sign-in records by the user and their place in the User table.
    /// </summary>
    Task DeleteUserAsync(string accountId);

    /// <summary>
    /// Signs a user out globally (all keys are deleted), such as in the instance 
    /// of someone else gaining access to their account.
    /// </summary>
    Task GlobalSignOutAsync(string accountId);

    /// <summary>
    /// Returns the Guid of a given account name. 
    /// </summary>
    Task<Guid> GetGuidAsync(string account);

    /// <summary>
    /// Returns the Role of a given account name. 
    /// </summary>
    Task<int> GetRoleAsync(string account);

    /// <summary>
    /// Retrieves the current number of sessions for a given user. 
    /// </summary>
    Task<int> GetCurrentSessionCountAsync(string account);

    /// <summary>
    /// Returns true if there exists a user with that account name. Swallows errors and returns false if not. 
    /// </summary>
    Task<bool> AccountExistsAsync(Guid account);

    /// <summary>
    /// Returns true if there exists a user with that account name. Swallows errors and returns false if not. 
    /// </summary>
    Task<bool> AccountExistsAsync(string account);

    /// <summary>
    /// Returns the first <c>limit</c> users, given their AccountName, from the query. 
    /// The query checks Contains, so in SQL '%{query}%'.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAsync(string query, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role greater than the given provided role. 
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAboveRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role greater than or equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAboveOrAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role less than or equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersBelowOrAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role less than the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersBelowRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the account name for the given user ID (Guid).
    /// </summary>
    Task<string> GetAccountNameAsync(Guid account);
}

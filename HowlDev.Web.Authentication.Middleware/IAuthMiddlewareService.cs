

namespace HowlDev.Web.Authentication.Middleware;

/// <summary/>
public interface IAuthMiddlewareService {
    /// <summary>
    /// Returns the user object from the given account. Throws an exception if the user does not exist.
    /// </summary>
    Task<Account> GetUserAsync(string account);

    /// <summary>
    /// Returns a date for when the API key was last updated in the <c>validatedOn</c> field.
    /// Throws an exception if no API key exists in the table. 
    /// </summary>
    /// <param name="accountName">Account used</param>
    /// <param name="key">API Key</param>
    /// <returns>Null or DateTime</returns>
    Task<DateTime> GetValidatedOnForKeyAsync(string accountName, string key);

    /// <summary>
    /// Updates the api key with the current DateTime value. This allows recently 
    /// signed-in users to continue being signed in on their key. It's primarily 
    /// used by my IdentityMiddleware and not recommended you use it on its own.
    /// </summary>
    Task ReValidateAsync(string accountId, string key);

    /// <summary>
    /// Sign out on an individual key. 
    /// </summary>
    Task KeySignOutAsync(string accountId, string key);

    /// <summary>
    /// Given the TimeSpan, remove keys from any user that are older than that length.
    /// </summary>
    Task ExpiredKeySignOutAsync(TimeSpan length);
}

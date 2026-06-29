using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Holds logic for validating accounts and keys in an endpoint, 
/// either in the middleware or on a filter.
/// </summary>
public partial class MiddlewareValidation(ILogger<MiddlewareValidation> _logger, IAuthMiddlewareService service) {
    // This line is needed to compile the [LoggerMessage] below.
    private readonly ILogger<MiddlewareValidation> logger = _logger;

    /// <summary>
    /// Runs through my validation checks to ensure the account is valid, the key is valid, and 
    /// the key isn't expired (if configured). <br/>
    /// Returns True if the middleware/filter should continue calling up the chain or should 
    /// return early. 
    /// </summary>
    /// <returns><c>True</c> if it should continue by calling next in the context</returns>
    public async Task<bool> RunMiddlewareValidationChecks(HttpContext context, string account, string key) {
        string? errorMessage = await TryFillingAccountInfo(context, account, key);
        if (errorMessage is not null) {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync(errorMessage);
            AuthMetrics.UnknownAccounts.Add(1);
            LogAccountName(account);
            return false;
        }

        DateTime? output = await service.GetValidatedOnForKeyAsync(account, key);
        if (output is null) {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("API key does not exist.");
            AuthMetrics.UnknownApiKeys.Add(1);
            LogUnknownKey(key);
            return false;
        }

        if (IdentityMiddleware.Config.ExpirationDate is null) {
            logger.LogDebug("Expiration date is null. Not performing any validation checks on the date.");
            return true;
        }

        TimeSpan timeBetween = DateTime.Now.ToUniversalTime() - (DateTime)output;
        if (timeBetween < IdentityMiddleware.Config.ExpirationDate) {
            if (IdentityMiddleware.Config.ReValidationDate is not null &&
                timeBetween > IdentityMiddleware.Config.ReValidationDate) {
                await service.ReValidateAsync(account, key);
                AuthMetrics.ResetKeys.Add(1);
                logger.LogInformation("Key was revalidated.");
            }
        } else {
            // Explicit cast removes the null check that's completed above
            await service.ExpiredKeySignOutAsync((TimeSpan)IdentityMiddleware.Config.ExpirationDate);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Time has run out. Please sign in again.");
            logger.LogInformation("Key was expired and removed.");
            AuthMetrics.ExpiredKeys.Add(1);
            return false;
        }

        return true;
    }

    private async Task<string?> TryFillingAccountInfo(HttpContext context, string account, string key) {
        Result<Account> acc = await service.TryGetUserAsync(account);
        if (acc.IsValid) {
            context.Items[MagicStrings.HttpContextGuid] = acc.Value.Id;
            context.Items[MagicStrings.HttpContextRole] = acc.Value.Role;
            context.Items[MagicStrings.HttpContextAcc] = account;
            context.Items[MagicStrings.HttpContextKey] = key;
        } else {
            return "Account does not exist.";
        }

        return null;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Account information could not be found. Searched for account: {account}")]
    private partial void LogAccountName(string account);

    [LoggerMessage(Level = LogLevel.Information, Message = "Could not find API key ({key}) in the table.")]
    private partial void LogUnknownKey(string key);
}

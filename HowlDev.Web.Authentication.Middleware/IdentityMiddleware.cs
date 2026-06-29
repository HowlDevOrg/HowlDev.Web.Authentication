using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Identity Middleware relies on the <c>IIDMiddlewareConfig</c> to be injected through DI, as well as an implementation 
/// of <c>IAuthMiddlewareService</c>. 
/// For any error, it will throw a <c>401</c> HTTP code with a string (of which 3 are user-friendly). Make sure 
/// the headers always contain a little bit of information, as the 4th is developer-intended. 
/// <br/> <br/>
/// This takes every path not in Paths of the config and checks for email and API Key headers. If they are 
/// null or empty, the response will give you the exact syntax. <br/>
/// Afterwards, they will validate that you have a valid API key, and return a short, helpful message if not so. <br/>
/// Finally, if the ExpirationDate is not null, it will calculate the time between. If it's over the expiration date, 
/// it will remove that key. If it's under but over the re-auth time (also assuming config), it will 
/// reset the expiration date. Then it will let the response pass. 
/// </summary>
public partial class IdentityMiddleware {
    private readonly RequestDelegate next;
    private readonly IAuthMiddlewareService service;
    private readonly ILogger<IdentityMiddleware> logger;
    /// <summary>
    /// The current configuration object for path bypass, headers, and 
    /// validation timeouts.
    /// </summary>
    public static IDMiddlewareConfig Config { get; private set; } = new();

    /// <summary/>
    public IdentityMiddleware(RequestDelegate _next, IAuthMiddlewareService _service, IDMiddlewareConfig _config, ILogger<IdentityMiddleware> _logger) {
        next = _next;
        service = _service;
        Config = _config;
        logger = _logger;
    }

    /// <summary/>
    public async Task InvokeAsync(HttpContext context) {
        logger.LogTrace("Entered middleware method.");
        string path = context.Request.Path.ToString();

        bool startsWith = false;
        if (Config.Whitelist is not null) {
            startsWith = !path.StartsWith(Config.Whitelist);
        }


        if (startsWith) {
            logger.LogDebug("Whitelist skipped authentication.");
            AuthMetrics.WhitelistPaths.Add(1);
            await next(context);
        } else if (Config.Paths.Any(c => c.Contains(path))) {
            logger.LogDebug("Paths excluded current request.");
            AuthMetrics.PathExclusions.Add(1);
            await next(context);
        } else if (Config.RegexPaths.Any(c => c.IsMatch(path))) {
            logger.LogDebug("Regex excluded current request.");
            AuthMetrics.RegexExclusions.Add(1);
            await next(context);
        } else {
            // Validate user here
            AuthMetrics.ValidatedRequests.Add(1);
            string? account = context.Request.Headers[Config.HeaderAccount];
            string? key = context.Request.Headers[Config.HeaderKey];
            if (string.IsNullOrEmpty(account) || string.IsNullOrEmpty(key)) {
                context.Response.StatusCode = 401;
                if (Config.DisableHeaderInfo) {
                    await context.Response.WriteAsync("Unauthorized: Missing header(s).");
                } else {
                    await context.Response.WriteAsync($"Unauthorized: Missing header(s).\nRequires an \"{Config.HeaderAccount}\" and \"{Config.HeaderKey}\" header.");
                }

                AuthMetrics.IncorrectHeaders.Add(1);
                logger.LogInformation("Two required headers were not found.");
                return;
            }

            string? errorMessage = await TryFillingAccountInfo(context, account, key);
            if (errorMessage is not null) {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync(errorMessage);
                AuthMetrics.UnknownAccounts.Add(1);
                LogAccountName(account);
                return;
            }

            DateTime? output = await service.GetValidatedOnForKeyAsync(account, key);
            if (output is not null) {
                LogDateResult(output);
            } else {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API key does not exist.");
                AuthMetrics.UnknownApiKeys.Add(1);
                LogUnknownKey(key);
                return;
            }

            if (Config.ExpirationDate is null) {
                logger.LogDebug("Expiration date is null. Not performing any validation checks on the date.");
                await next(context);
                return;
            }


            TimeSpan timeBetween = DateTime.Now.ToUniversalTime() - (DateTime)output;
            if (timeBetween < Config.ExpirationDate) {
                LogTimeRemaining(timeBetween);
                if (Config.ReValidationDate is not null &&
                    timeBetween > Config.ReValidationDate) {
                    await service.ReValidateAsync(account, key);
                    AuthMetrics.ResetKeys.Add(1);
                    logger.LogInformation("Key was revalidated.");
                }

                await next(context);
            } else {
                // Explicit cast removes the null check that's completed above
                await service.ExpiredKeySignOutAsync((TimeSpan)Config.ExpirationDate);
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Time has run out. Please sign in again.");
                logger.LogInformation("Key was expired and removed.");
                AuthMetrics.ExpiredKeys.Add(1);
            }
        }

        logger.LogTrace("Exiting middleware method.");
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

    [LoggerMessage(Level = LogLevel.Trace, Message = "Found a date value ({output})")]
    private partial void LogDateResult(DateTime? output);

    [LoggerMessage(Level = LogLevel.Trace, Message = "Found date was not past the calculated expiration date. There is still ({timespan}) time left.")]
    private partial void LogTimeRemaining(TimeSpan? timespan);

    [LoggerMessage(Level = LogLevel.Information, Message = "Could not find API key ({key}) in the table.")]
    private partial void LogUnknownKey(string key);
}

using System.ComponentModel;
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
    private readonly ILogger<IdentityMiddleware> logger;
    /// <summary>
    /// The current configuration object for path bypass, headers, and 
    /// validation timeouts.
    /// </summary>
    public static IDMiddlewareConfig Config { get; private set; } = new();
    /// <summary>
    /// Internal validator class for validating HttpContext values and 
    /// authentication. <br/>
    /// Only designed for internal use. 
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static MiddlewareValidation? Validator { get; private set; }

    /// <summary/>
    public IdentityMiddleware(RequestDelegate _next, MiddlewareValidation _validator, IDMiddlewareConfig _config, ILogger<IdentityMiddleware> _logger) {
        next = _next;
        logger = _logger;
        Config = _config;
        Validator = _validator;
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

            bool runNextInContext = await Validator!.RunMiddlewareValidationChecks(context, account, key);
            if (runNextInContext) {
                await next(context);
            }
        }

        logger.LogTrace("Exiting middleware method.");
    }
}

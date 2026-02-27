using System.Text.RegularExpressions;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Configure certain parts of your middleware, such as un-authenticated paths, and (optionally)
/// the expiration dates of keys and when you want to re-validate their key for longer usage. 
/// </summary>
public class IDMiddlewareConfig {
    /// <summary>
    /// Set to the list of paths that you want the middleware  
    /// to exclude authorization.
    /// </summary>
    public List<string> Paths { get; set; } = [];

    /// <summary>
    /// After checking Whitelist and Paths, run through any RegexPaths that return a valid match to 
    /// the regex provided. 
    /// </summary>
    public List<Regex> RegexPaths { get; set; } = [];

    /// <summary>
    /// If not null, the middleware will only check paths that start with this 
    /// path. For example, in some projects, all API calls start with <c>/api</c>, so adding 
    /// that will only check paths that start with <c>/api</c>. 
    /// </summary>
    public string? Whitelist { get; set; }

    /// <summary>
    /// Set to the timespan that API keys are valid for. <c>Null</c> enables no time validation. 
    /// </summary>
    public TimeSpan? ExpirationDate { get; set; }

    /// <summary>
    /// If set to <c>null</c>, does nothing. Otherwise, set it to a timespan so if their key is still 
    /// valid, reset the expiration date for their API key. 
    /// </summary>
    public TimeSpan? ReValidationDate { get; set; }

    /// <summary>
    /// Enables all levels of Traces, Debug, Information, and Error 
    /// in the IdentityMiddleware. Set different logging levels in appsettings.json.
    /// </summary>
    public bool EnableLogging { get; set; }

    /// <summary>
    /// Removes detailed error messages with invalid headers. As you shouldn't broadcast 
    /// what headers are needed to bypass an authentication middleware, this should be disabled 
    /// in production (and after you get your frontend API calls set up). 
    /// </summary>
    public bool DisableHeaderInfo { get; set; }

    /// <summary>
    /// Specify the header name for the account name which the middleware checks for valid account names. <br/>
    /// Defaults to "Account-Auth-Account".
    /// </summary>
    public string HeaderAccount { get; set; } = "Account-Auth-Account";

    /// <summary>
    /// Specify the header name for the api key which the middleware checks for valid keys. <br/>
    /// Default to "Account-Auth-ApiKey".
    /// </summary>
    public string HeaderKey { get; set; } = "Account-Auth-ApiKey";
}

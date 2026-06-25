using System.Diagnostics.Metrics;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Provides a few metrics for middleware-specific actions. The 
/// string to use is <c>HowlDev.Web.Authentication.Middleware</c>. 
/// </summary>
public static class AuthMetrics {
    private static readonly Meter _meter = new("HowlDev.Web.Authentication.Middleware");

    /// <summary>
    /// Count of how many keys had their timer reset.
    /// </summary>
    public static readonly Counter<int> ResetKeys =
        _meter.CreateCounter<int>("auth_reset_keys");

    /// <summary>
    /// Count of how many keys have expired and been removed. 
    /// </summary>
    public static readonly Counter<int> ExpiredKeys =
        _meter.CreateCounter<int>("auth_expired_keys");

    /// <summary>
    /// Count of how many keys could not be found.
    /// </summary>
    public static readonly Counter<int> UnknownApiKeys =
        _meter.CreateCounter<int>("auth_unknown_keys");

    /// <summary>
    /// Count of how many accounts could not be found.
    /// </summary>
    public static readonly Counter<long> UnknownAccounts =
        _meter.CreateCounter<long>("auth_unknown_accounts");

    /// <summary>
    /// Count of how many requests had incorrect headers.
    /// </summary>
    public static readonly Counter<long> IncorrectHeaders =
        _meter.CreateCounter<long>("auth_incorrect_headers");

    /// <summary>
    /// Count of how many requests were whitelisted past the 
    /// middleware.
    /// </summary>
    public static readonly Counter<long> WhitelistPaths =
        _meter.CreateCounter<long>("auth_whitelisted_requests");

    /// <summary>
    /// Count of how many requests were whitelisted via the 
    /// Path parameter past the middleware.
    /// </summary>
    public static readonly Counter<long> PathExclusions =
        _meter.CreateCounter<long>("auth_path_excluded_requests");

    /// <summary>
    /// Count of how many requests were whitelisted via the 
    /// Regex parameter past the middleware.
    /// </summary>
    public static readonly Counter<long> RegexExclusions =
        _meter.CreateCounter<long>("auth_regex_excluded_requests");

    /// <summary>
    /// Count of how many requests were whitelisted via the 
    /// Regex parameter past the middleware.
    /// </summary>
    public static readonly Counter<long> ValidatedRequests =
        _meter.CreateCounter<long>("auth_validated_requests");
}

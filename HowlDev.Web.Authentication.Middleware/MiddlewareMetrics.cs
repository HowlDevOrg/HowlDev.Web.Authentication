using System.Diagnostics.Metrics;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Provides a few metrics for middleware-specific actions. The 
/// string to use is <c>HowlDev.Web.Authentication.Middleware</c>. 
/// </summary>
public static class AuthMetrics {
    private static readonly Meter _meter = new("HowlDev.Web.Authentication.Middleware", "1.0.0");

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
}

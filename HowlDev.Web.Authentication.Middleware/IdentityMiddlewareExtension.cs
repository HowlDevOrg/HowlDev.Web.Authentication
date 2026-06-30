using Microsoft.AspNetCore.Builder;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Unused XML comment
/// </summary>
public static class IdentityMiddlewareExtension {
    /// <summary>
    /// Enables the Identity Middleware for AccountAuthenticator. Create a lambda to configure options
    /// previously held in IIDMiddlewareConfig, with an example below.
    /// <code>
    /// app.UseAccountIdentityMiddleware(MiddlewareLocation.Headers, options => {
    ///   options.Paths = ["/users", "/user", "/user/signin"];
    ///   options.Whitelist = "/data";
    ///   options.ExpirationDate = new TimeSpan(30, 0, 0, 0);
    ///   options.ReValidationDate = new TimeSpan(5, 0, 0, 0);
    ///   // other options as seen in Intellisense
    /// });
    /// </code>
    /// Also enables the AccountInfo parameter, which is an encapsulation for username, key, and 
    /// Guid of the incoming user. 
    /// </summary>
    public static IApplicationBuilder UseAccountIdentityMiddleware(this IApplicationBuilder app, MiddlewareLocation location, Action<IDMiddlewareConfig>? configureOptions = null) {
        var options = new IDMiddlewareConfig();
        configureOptions?.Invoke(options);

        return app.UseMiddleware<IdentityMiddleware>(options);
    }
}

/// <summary>
/// Determines where the middleware looks to get information from the context. <br/>
/// In the future, this will include Cookies and an OIDC client, but this is 
/// a bit of a placeholder so I can keep this without major (semver) updates 
/// to this library. Will be used later. 
/// </summary>
public enum MiddlewareLocation {
    /// <summary>
    /// Gets the AccountName and ApiKey from the Header, where specified in the 
    /// IDMiddlewareConfig.
    /// </summary>
    Headers
}

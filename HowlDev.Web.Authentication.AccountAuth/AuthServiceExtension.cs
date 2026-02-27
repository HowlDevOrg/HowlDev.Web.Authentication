using HowlDev.Web.Authentication.AccountAuth.Interfaces;
using HowlDev.Web.Authentication.Middleware;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// Unused XML comment
/// </summary>
public static class IdentityMiddlewareExtension {
    /// <summary>
    /// Injects the AuthService as both an IAuthService type and an IAuthMiddlewareService type
    /// to satisfy both. 
    /// </summary>
    public static WebApplicationBuilder AddAuthService(this WebApplicationBuilder builder) {
        builder.Services.AddSingleton<AuthService>();
        builder.Services.AddSingleton<IAuthService, AuthService>();
        builder.Services.AddSingleton<IAuthMiddlewareService, AuthService>();
        return builder;
    }
}

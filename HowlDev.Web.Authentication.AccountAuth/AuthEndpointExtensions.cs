using HowlDev.Web.Authentication.Middleware;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// This class contains the <see cref="TrySetAccountInformation"/> method 
/// which, if the context contains the proper headers, validates and 
/// sets account information for a <see cref="TryAccountInfo"/> input.
/// </summary>
public static class AuthEndpointExtensions {
    /// <summary>
    /// If the context contains header information, performs the standard middleware 
    /// checks (and fills information for <see cref="TryAccountInfo"/>) and returns early 
    /// if there's a problem. Otherwise, lets the request pass through silently. 
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="index">Index of the TryAccountInfo parameter (0-indexed)</param>
    public static RouteHandlerBuilder TrySetAccountInformation(
        this RouteHandlerBuilder builder, int index) {
        return builder.AddEndpointFilter(async (context, next) => {
            (string? account, string? key) = MiddlewareValidation.GetContextHeaders(context.HttpContext);
            if (account is not null && key is not null) {
                MiddlewareValidation validator = context.HttpContext.RequestServices.GetRequiredService<MiddlewareValidation>();
                bool isValidKey = await validator.RunMiddlewareValidationChecks(context.HttpContext, account, key);
                if (!isValidKey) {
                    // Here, it should implicitly come back with the information set in the validator. 
                    return null;
                } else {
                    context.Arguments[index] = new TryAccountInfo(context.HttpContext);
                    return await next(context);
                }
            } else {
                return await next(context);
            }
        });
    }
}

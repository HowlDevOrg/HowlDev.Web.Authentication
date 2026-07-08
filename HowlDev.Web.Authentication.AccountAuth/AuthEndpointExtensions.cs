using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using HowlDev.Web.Authentication.Middleware;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HowlDev.Web.Authentication.AccountAuth;

/// <summary>
/// This class contains the <c>TrySetAccountInformation</c> methods 
/// which, if the context contains the proper headers, validates and 
/// sets account information for a <see cref="TryAccountInfo"/> input.
/// </summary>
public static class AuthEndpointExtensions {
    /// <summary>
    /// If the context contains header information, performs the standard middleware 
    /// checks (and fills information for <see cref="TryAccountInfo"/>) and returns early 
    /// if there's a problem. Otherwise, lets the request pass through silently. <br/>
    /// Uses reflection (slightly slower) to make it a bit easier to use.
    /// </summary>
    /// <param name="builder"></param>
    public static RouteHandlerBuilder TrySetAccountInformation(
        this RouteHandlerBuilder builder) {
        return builder.AddEndpointFilter(async (context, next) => {
            (string? account, string? key) = MiddlewareValidation.GetContextHeaders(context.HttpContext);
            ILogger<TrySetAccountInfoLogger> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<TrySetAccountInfoLogger>>();
            if (!string.IsNullOrWhiteSpace(account) && !string.IsNullOrWhiteSpace(key)) {
                MiddlewareValidation validator = context.HttpContext.RequestServices.GetRequiredService<MiddlewareValidation>();

                logger.LogTrace("Running validation checks inside TrySetAccountInfo.");
                bool isValidKey = await validator.RunMiddlewareValidationChecks(context.HttpContext, account, key);
                if (!isValidKey) {
                    logger.LogTrace("Failed to validate key.");
                    // Here, it should implicitly come back with the information set in the validator. 
                    return null;
                } else {
                    logger.LogTrace("Key was validated.");
                    // This segment was written by AI.
                    var endpoint = context.HttpContext.GetEndpoint();
                    var methodInfo = endpoint?.Metadata.GetMetadata<MethodInfo>();

                    if (methodInfo is not null) {
                        var parameters = methodInfo.GetParameters();
                        bool validated = false;
                        for (int i = 0; i < parameters.Length; i++) {
                            if (context.Arguments[i] is TryAccountInfo) {
                                context.Arguments[i] = new TryAccountInfo(context.HttpContext);
                                validated = true;
                                break;
                            }
                        }

                        Debug.Assert(validated, "Make sure you pass in a TryAccountInfo parameter.");
                    }

                    return await next(context);
                }
            } else {
                logger.LogTrace("Account or key was invalid, bypassing TrySetAccountInfo.");
                return await next(context);
            }
        });
    }

    /// <summary>
    /// If the context contains header information, performs the standard middleware 
    /// checks (and fills information for <see cref="TryAccountInfo"/>) and returns early 
    /// if there's a problem. Otherwise, lets the request pass through silently. <br/>
    /// For a more performant path if you want to avoid some reflection. <br/>
    /// Uses a Debug flag to validate that the index provided is within the expected 
    /// bounds (uses some reflection).
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="index">Index of the TryAccountInfo parameter (0-indexed)</param>
    public static RouteHandlerBuilder TrySetAccountInformation(
        this RouteHandlerBuilder builder, int index) {
        return builder.AddEndpointFilter(async (context, next) => {
            (string? account, string? key) = MiddlewareValidation.GetContextHeaders(context.HttpContext);
            ILogger<TrySetAccountInfoLogger> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<TrySetAccountInfoLogger>>();
            if (!string.IsNullOrWhiteSpace(account) && !string.IsNullOrWhiteSpace(key)) {
                MiddlewareValidation validator = context.HttpContext.RequestServices.GetRequiredService<MiddlewareValidation>();
                logger.LogTrace("Running validation checks inside TrySetAccountInfo.");
                bool isValidKey = await validator.RunMiddlewareValidationChecks(context.HttpContext, account, key);
                if (!isValidKey) {
                    logger.LogTrace("Failed to validate key.");
                    // Here, it should implicitly come back with the information set in the validator. 
                    return null;
                } else {
                    logger.LogTrace("Key was validated.");
                    ValidateIndexWithinBounds(index, context);

                    context.Arguments[index] = new TryAccountInfo(context.HttpContext);
                    return await next(context);
                }
            } else {
                logger.LogTrace("Account or key was invalid, bypassing TrySetAccountInfo.");
                return await next(context);
            }
        });
    }

    [Conditional("DEBUG")]
    private static void ValidateIndexWithinBounds(int index, EndpointFilterInvocationContext context) {
        // This segment was written by AI.
        // Included so I can throw errors with Debug.
        var endpoint = context.HttpContext.GetEndpoint();
        var methodInfo = endpoint?.Metadata.GetMetadata<MethodInfo>();

        if (methodInfo is not null) {
            Debug.Assert(index < methodInfo.GetParameters().Length,
                "Index must be less than the length of the parameters.");
        }
    }
}

/// <summary>
/// Class generated for prettier text in Trace logs.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public class TrySetAccountInfoLogger { }

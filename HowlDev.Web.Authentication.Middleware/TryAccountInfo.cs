using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace HowlDev.Web.Authentication.Middleware;

/// <summary>
/// Encapsulates Account Name, ApiKey, Role, and Guid of the incoming request. 
/// Enables smoother encapsulation for endpoints, just use this as a parameter and it 
/// will collect the information for you, or appropriately throw errors. 
/// </summary>
public class TryAccountInfo {
    /// <summary>
    /// Account Name of the incoming request
    /// </summary>
    public string? AccountName { get; }
    /// <summary>
    /// Api Key of the incoming request
    /// </summary>
    public string? ApiKey { get; }
    /// <summary>
    /// Guid of the incoming request
    /// </summary>
    public Guid? Guid { get; }
    /// <summary>
    /// Role of the incoming user
    /// </summary>
    public int? Role { get; }
    /// <summary>
    /// The values in this object are valid
    /// </summary>
    [MemberNotNullWhen(true, nameof(AccountName))]
    [MemberNotNullWhen(true, nameof(ApiKey))]
    [MemberNotNullWhen(true, nameof(Guid))]
    [MemberNotNullWhen(true, nameof(Role))]
    public bool IsValid { get; }

    private TryAccountInfo() {
        IsValid = false;
    }

    /// <summary>
    /// Only used for internal use. Do not use. Inject it with parameters
    /// in your endpoints. 
    /// </summary>
    public TryAccountInfo(HttpContext context) {
        AccountName = (string)context.Items[MagicStrings.HttpContextAcc]!;
        ApiKey = (string)context.Items[MagicStrings.HttpContextKey]!;
        Guid = (Guid)context.Items[MagicStrings.HttpContextGuid]!;
        Role = (int)context.Items[MagicStrings.HttpContextRole]!;
        IsValid = true;
    }

    /// <summary>
    /// Is this even visible? I don't think so. 
    /// </summary>
    public static ValueTask<TryAccountInfo> BindAsync(HttpContext context) {
        if (context.Items.ContainsKey(MagicStrings.HttpContextAcc)) {
            throw new Exception("This path is already covered by the Auth middleware. Use AccountInfo instead.");
        }

        return ValueTask.FromResult(new TryAccountInfo());
    }
}

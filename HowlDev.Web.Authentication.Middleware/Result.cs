#pragma warning disable IDE0130, CA1815
using System.Diagnostics.CodeAnalysis;

namespace HowlDev.Web.Authentication;

/// <summary>
/// Returns a wrapper that contains a valid value, if the 
/// operation creating it was successful. 
/// </summary>
/// <typeparam name="T">Type to wrap</typeparam>
public readonly struct Result<T> {
    /// <summary>
    /// For Invalid operations. Sets IsValid to <c>false</c>. Does nothing 
    /// to the Value field.
    /// </summary>
    public Result() {
        IsValid = false;
    }

    /// <summary>
    /// For valid values, automatically sets IsValid to <c>true</c>. 
    /// </summary>
    public Result(T value) {
        Value = value;
        IsValid = true;
    }

    /// <summary>
    /// Is True if the internal value is a valid value.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Value))]
    public bool IsValid { get; }

    /// <summary>
    /// If <see cref="IsValid"/> is <c>true</c>, contains a valid object.
    /// </summary>
    public T? Value { get; }
}

namespace BD.WTTS.Models;

/// <inheritdoc cref="IGAPAuthenticatorDTO"/>
[MessagePackObject(keyAsPropertyName: true)]
public sealed partial class AuthenticatorDTO : IAuthenticatorDTO
{
    [MPIgnore, N_JsonIgnore, S_JsonIgnore]
    public ushort Id { get; set; }

    public int Index { get; set; }

    public string Name { get; set; } = string.Empty;

    [MPIgnore, N_JsonIgnore, S_JsonIgnore]
    public AuthenticatorPlatform Platform => Value == null ? default : Value.Platform;

    public Guid? ServerId { get; set; }

    public DateTimeOffset Created { get; set; }

    public DateTimeOffset LastUpdate { get; set; }

    public IAuthenticatorValueDTO? Value { get; set; }

    bool IExplicitHasValue.ExplicitHasValue()
    {
        return !string.IsNullOrEmpty(Name) && Value != null;
    }
}

[Obsolete("use AuthenticatorDTO", true)]
public sealed class GAPAuthenticatorDTO
{

}
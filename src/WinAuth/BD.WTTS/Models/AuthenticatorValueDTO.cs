// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models;

public partial class AuthenticatorValueDTO : IAuthenticatorValueDTO
{
    public AuthenticatorValueDTO()
    {

    }

    protected virtual bool ExplicitHasValue()
    {
        return SecretKey != null && CodeDigits > 0 && HMACType.IsDefined() && Period > 0;
    }

    bool IExplicitHasValue.ExplicitHasValue() => ExplicitHasValue();
}
namespace WinAuth;

public class TOTPAuthenticator : GoogleAuthenticator
{
    /// <summary>
    /// Create a new Authenticator object
    /// </summary>
    [SerializationConstructor]
    public TOTPAuthenticator() : base()
    {
    }

    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public override AuthenticatorPlatform Platform => AuthenticatorPlatform.TOTP;

    public override void Sync()
    {

    }
}

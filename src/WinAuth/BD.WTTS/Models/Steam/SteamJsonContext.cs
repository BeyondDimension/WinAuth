using WinAuth;

namespace BD.WTTS.Models;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SteamGetRsaKeyJsonStruct))]
[JsonSerializable(typeof(SteamDoLoginJsonStruct))]
[JsonSerializable(typeof(SteamDoLoginOauthJsonStruct))]
[JsonSerializable(typeof(SteamDoLoginHasPhoneJsonStruct))]
[JsonSerializable(typeof(SteamDoLoginTfaJsonStruct))]
[JsonSerializable(typeof(SteamDoLoginFinalizeJsonStruct))]
[JsonSerializable(typeof(SteamSyncStruct))]
[JsonSerializable(typeof(SteamConvertSteamDataJsonStruct))]
[JsonSerializable(typeof(SteamMobileDologinJsonStruct))]
[JsonSerializable(typeof(SteamMobileConfGetListJsonStruct))]
[JsonSerializable(typeof(RemoveAuthenticatorResponse))]
public partial class SteamJsonContext : JsonSerializerContext
{
}

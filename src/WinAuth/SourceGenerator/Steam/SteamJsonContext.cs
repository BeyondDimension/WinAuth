using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static WinAuth.SteamClient;

namespace WinAuth
{
    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(SteamGetRsaKeyJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginOauthJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginHasPhoneJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginTfaJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginFinalizeJsonStruct))]
    [JsonSerializable(typeof(SteamSyncStruct))]
    [JsonSerializable(typeof(SteamSessionDataStruct))]
    [JsonSerializable(typeof(SteamRefreshJsonStruct))]
    [JsonSerializable(typeof(SteamGetConfirmationJsonStruct))]
    public partial class SteamJsonContext : JsonSerializerContext
    {
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinAuth
{
    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(SteamGetRsaKeyJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginHasPhoneJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginTfaJsonStruct))]
    [JsonSerializable(typeof(SteamDoLoginFinalizeJsonStruct))]
    [JsonSerializable(typeof(SteamSyncStruct))]
    internal partial class SteamJsonContext : JsonSerializerContext
    {
    }
}

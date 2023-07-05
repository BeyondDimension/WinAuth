namespace BD.WTTS.Models;

[JsonSerializable(typeof(GetUserCountryResponse))]
[JsonSerializable(typeof(SteamAddPhoneNumberResponse))]
[JsonSerializable(typeof(IsAccountWaitingForEmailConfirmationResponse))]
public partial class SteamPhoneNumberJsonContext : JsonSerializerContext
{

}
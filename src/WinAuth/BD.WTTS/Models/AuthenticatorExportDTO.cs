using static BD.WTTS.Models.Abstractions.IAuthenticatorValueDTO;

namespace BD.WTTS.Models;

/// <summary>
/// 令牌数据轻量化导出模型
/// </summary>
[MPObj, MP2Obj(SerializeLayout.Explicit)]
public sealed partial class AuthenticatorExportDTO
{
    [MPKey(0), MP2Key(0)]
    public AuthenticatorPlatform Platform { get; set; }

    [MPKey(1), MP2Key(1)]
    public string? Issuer { get; set; }

    [MPKey(2), MP2Key(2)]
    public HMACTypes HMACType { get; set; }

    [MPKey(3), MP2Key(3)]
    public string? Serial { get; set; }

    [MPKey(4), MP2Key(4)]
    public string? DeviceId { get; set; }

    [MPKey(5), MP2Key(5)]
    public string? SteamData { get; set; }

    [MPKey(6), MP2Key(6)]
    public long Counter { get; set; }

    [MPKey(7), MP2Key(7)]
    public int Period { get; set; }

    [MPKey(8), MP2Key(8)]
    public byte[]? SecretKey { get; set; }

    [MPKey(9), MP2Key(9)]
    public int CodeDigits { get; set; }

    [MPKey(10), MP2Key(10)]
    public string Name { get; set; } = string.Empty;

    public override string ToString() => this.ToUrl();
}
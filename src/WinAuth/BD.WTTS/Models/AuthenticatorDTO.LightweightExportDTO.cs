using static BD.WTTS.Models.Abstractions.IAuthenticatorValueDTO;

namespace BD.WTTS.Models;

partial class AuthenticatorDTO
{
    /// <summary>
    /// 轻量化导出模型
    /// </summary>
    [MPObj]
    public sealed class LightweightExportDTO
    {
        [MPKey(0)]
        public AuthenticatorPlatform Platform { get; set; }

        [MPKey(1)]
        public string? Issuer { get; set; }

        [MPKey(2)]
        public HMACTypes HMACType { get; set; }

        [MPKey(3)]
        public string? Serial { get; set; }

        [MPKey(4)]
        public string? DeviceId { get; set; }

        [MPKey(5)]
        public string? SteamData { get; set; }

        [MPKey(6)]
        public long Counter { get; set; }

        [MPKey(7)]
        public int Period { get; set; }

        [MPKey(8)]
        public byte[]? SecretKey { get; set; }

        [MPKey(9)]
        public int CodeDigits { get; set; }

        [MPKey(10)]
        public string Name { get; set; } = string.Empty;

        public override string ToString() => this.ToUrl();
    }
}
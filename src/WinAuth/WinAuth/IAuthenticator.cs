using System.Xml;

// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models.Abstractions;

partial interface IAuthenticatorValueDTO
{
    /// <summary>
    /// 使用当前加密和/或密码保存的当前数据（可能为无）
    /// </summary>
    string? EncryptedData { get; set; }

    /// <summary>
    /// 服务器时间戳
    /// </summary>
    long ServerTime { get; }

    /// <summary>
    /// Type of password to use to encrypt secret data
    /// </summary>
    public enum PasswordTypes
    {
        None = 0,
        Explicit = 1,
        User = 2,
        Machine = 4,
        YubiKeySlot1 = 8,
        YubiKeySlot2 = 16,
    }

    /// <summary>
    /// 用于加密机密数据的密码类型
    /// </summary>
    PasswordTypes PasswordType { get; set; }

    bool RequiresPassword { get; }

    /// <summary>
    /// 发行者名称
    /// </summary>
    string? Issuer { get; set; }

    /// <summary>
    /// 获取/设置组合的机密数据值
    /// </summary>
    string? SecretData { get; set; }

    /// <summary>
    /// 根据计算的服务器时间计算代码间隔
    /// </summary>
    long CodeInterval { get; }

    /// <summary>
    /// 获取验证器的当前代码
    /// </summary>
    string CurrentCode { get; }

    /// <summary>
    /// 将此验证器的时间与服务器时间同步。我们用UTC时间的差值更新数据记录
    /// </summary>
    void Sync();

    void Protect();

    bool Unprotect(string? password);

    bool ReadXml(XmlReader reader, string? password = null);
}
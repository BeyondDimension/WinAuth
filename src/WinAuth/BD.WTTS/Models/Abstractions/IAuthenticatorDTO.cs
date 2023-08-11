// ReSharper disable once CheckNamespace
namespace BD.WTTS.Models.Abstractions;

/// <summary>
/// 身份验证器(游戏平台令牌)可传输模型
/// </summary>
public interface IAuthenticatorDTO : IOrderAuthenticator, IExplicitHasValue
{
    const int MaxLength_Name = 32;

    string Name { get; set; }

    AuthenticatorPlatform Platform { get; }

    Guid? ServerId { get; set; }

    public DateTimeOffset Created { get; set; }

    public DateTimeOffset LastUpdate { get; set; }

    /// <summary>
    /// 身份验证器(游戏平台令牌)数据值
    /// </summary>
    IAuthenticatorValueDTO Value { get; set; }
}
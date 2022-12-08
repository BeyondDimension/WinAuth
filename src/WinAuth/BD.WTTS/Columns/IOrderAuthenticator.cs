// ReSharper disable once CheckNamespace
namespace BD.WTTS.Columns;

/// <summary>
/// 可排序的身份验证器
/// </summary>
public interface IOrderAuthenticator
{
    ushort Id { get; set; }

    int Index { get; set; }
}

[Obsolete("use IOrderAuthenticator", true)]
public interface IOrderGAPAuthenticator : IOrderAuthenticator
{

}
// C# 10 定义全局 using

#if !NETFRAMEWORK
global using System.Collections.Immutable;
#endif
global using System.Diagnostics;
global using System.Diagnostics.CodeAnalysis;
global using System.Globalization;
global using System.Linq;
global using System.Net;
global using System.Net.Http.Headers;
global using System.Reflection;
global using System.Runtime.CompilerServices;
global using System.Runtime.Serialization;
global using System.Security.Cryptography;
global using System.Text;
global using System.Text.Json;
global using System.Text.Json.Serialization;
global using System.Text.RegularExpressions;
global using System.Runtime.Devices;

#if MVVM_VM
global using DynamicData;
global using DynamicData.Binding;
global using System.Collections.ObjectModel;
global using System.Reactive.Linq;
#endif


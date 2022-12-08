// C# 10 定义全局 using

global using BD.Common;
global using BD.Common.Columns;
global using BD.Common.Enums;
#if _IMPORT_COMMON_CONTROLLERS__
global using BD.Common.Controllers;
global using BD.Common.Controllers.Abstractions;
#endif
#if _IMPORT_COMMON_IDENTITY__
global using BD.Common.Identity;
global using BD.Common.Identity.Abstractions;
#endif
#if _IMPORT_COMMON_SERVICES__
global using BD.Common.Services;
#endif
#if USE_SMS
global using BD.Common.Models.SmsSender;
global using BD.Common.Services.Implementation.SmsSender;
#endif
#if _IMPORT_COMMON_MIDDLEWARE__
global using BD.Common.Middleware;
#endif
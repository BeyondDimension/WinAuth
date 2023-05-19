// C# 10 定义全局 using

#if __HAVE_N_JSON__
global using N_JsonIgnore = Newtonsoft.Json.JsonIgnoreAttribute;
#endif
#if !__NOT_HAVE_S_JSON__
global using S_JsonIgnore = System.Text.Json.Serialization.JsonIgnoreAttribute;
#endif
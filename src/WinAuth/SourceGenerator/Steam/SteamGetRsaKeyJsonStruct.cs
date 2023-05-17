using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinAuth
{
    sealed class SteamGetRsaKeyJsonStruct
    {
        public bool Success { get; set; }

        public string Publickey_mod { get; set; } = string.Empty;

        public string Publickey_exp { get; set; } = string.Empty;

        public string Timestamp { get; set; } = string.Empty;

        public string Token_gid { get; set; } = string.Empty;
    }
}

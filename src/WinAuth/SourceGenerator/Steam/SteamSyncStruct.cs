using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinAuth
{
    sealed class SteamSyncStruct
    {
        public SteamSyncResponseStruct Response { get; set; }
    }

    sealed class SteamSyncResponseStruct
    {
        public string Server_time { get; set; } = string.Empty;

        public string Skew_tolerance_seconds { get; set; } = string.Empty;

        public string Large_time_jink { get; set; } = string.Empty;

        public int Probe_frequency_seconds { get; set; }

        public int Adjusted_time_probe_frequency_seconds { get; set; }

        public int Hint_probe_frequency_seconds { get; set; }

        public int Sync_timeout { get; set; }

        public int Try_again_seconds { get; set; }

        public int Max_attempts { get; set; }

    }

}

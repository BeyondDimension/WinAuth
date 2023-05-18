using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinAuth
{
    sealed class SteamSyncStruct
    {
        [JsonPropertyName("response")]
        public SteamSyncResponseStruct Response { get; set; }
    }

    sealed class SteamSyncResponseStruct
    {
        [JsonPropertyName("server_time")]
        public string ServerTime { get; set; } = string.Empty;

        [JsonPropertyName("skew_tolerance_seconds")]
        public string SkewToleranceSeconds { get; set; } = string.Empty;

        [JsonPropertyName("large_time_jink")]
        public string LargeTimeJink { get; set; } = string.Empty;

        [JsonPropertyName("probe_frequency_seconds")]
        public int ProbeFrequencySeconds { get; set; }

        [JsonPropertyName("adjusted_time_probe_frequency_seconds")]
        public int AdjustedTimeProbeFrequencySeconds { get; set; }

        [JsonPropertyName("hint_probe_frequency_seconds")]
        public int HintProbeFrequencySeconds { get; set; }

        [JsonPropertyName("sync_timeout")]
        public int SyncTimeOut { get; set; }

        [JsonPropertyName("try_again_seconds")]
        public int TryAgainSeconds { get; set; }

        [JsonPropertyName("max_attempts")]
        public int MaxAttempts { get; set; }

    }

}

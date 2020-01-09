//using System.Runtime.Serialization;

namespace Cinegy.TsAnalysis.Metrics
{
    public class TsMetric 
    {
         
        public int PidCount { get; set; }

         
        public int PidPackets { get; set; }

         
        public int PidCcErrors { get; set; }

         
        public int TeiErrors { get; set; }

         
        public int LongestPcrDelta { get; set; }

         
        public float LargestPcrDrift { get; set; }

         
        public float LowestPcrDrift { get; set; }
    }
}

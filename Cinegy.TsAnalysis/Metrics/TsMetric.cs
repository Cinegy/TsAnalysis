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

         
        public int LargestPcrDrift { get; set; }

         
        public int LowestPcrDrift { get; set; }
    }
}

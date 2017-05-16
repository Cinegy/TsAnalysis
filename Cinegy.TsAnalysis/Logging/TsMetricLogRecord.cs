//using System.Runtime.Serialization;

using Cinegy.TsAnalysis.Metrics;

namespace Cinegy.TsAnalysis.Logging
{
  //  [DataContract]
    public class TsMetricLogRecord
    {
    //    [DataMember]
        public NetworkMetric Net { get; set; }

      //  [DataMember]
        public RtpMetric Rtp { get; set; }

        //[DataMember]
        public TsMetric Ts { get; set; }
    }
}

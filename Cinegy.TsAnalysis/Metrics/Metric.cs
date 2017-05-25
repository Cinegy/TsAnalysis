using System;
using System.Threading;

//using System.Runtime.Serialization;

namespace Cinegy.TsAnalysis.Metrics
{
    public abstract class Metric
    {
        private int _samplingPeriod = 5000;
        private Timer _periodTimer;

        internal readonly long TicksPerSecond;
        internal DateTime StartTime;

        protected Metric(int samplingPeriod)
        {
            TicksPerSecond = new TimeSpan(0, 0, 0, 1).Ticks;
            SamplingPeriod = samplingPeriod;
            _periodTimer = new Timer(ResetPeriodTimerCallback, null, 0, SamplingPeriod);
        }
        
        public string SampleTime => DateTime.UtcNow.ToString("o");
        
        public string LastPeriodEndTime { get; private set; }

        public long SampleCount { get; private set; }

        /// <summary>
        /// Defines the internal sampling period in milliseconds - each time the sampling period has rolled over during packet addition, the periodic values reset.
        /// The values returned by all 'Period' properties represent the values gathered within the last completed period.
        /// </summary>
        public int SamplingPeriod
        {
            get { return _samplingPeriod; }
            set
            {
                _samplingPeriod = value;
                ResetPeriodTimerCallback(null);
                _periodTimer = new Timer(ResetPeriodTimerCallback, null, 0, SamplingPeriod);

            }
        }

        internal virtual void ResetPeriodTimerCallback(object o)
        {
            lock (this)
            {
                LastPeriodEndTime = SampleTime;

                SampleCount++;

            }
        }
    }
}

using System;
using System.Diagnostics;
using Cinegy.TsDecoder.TransportStream;

//using System.Runtime.Serialization;

namespace Cinegy.TsAnalysis.Metrics
{
    public delegate void DiscontinuityDetectedEventHandler(object sender, TransportStreamEventArgs args);
    public delegate void TransportErrorIndicatorDetectedEventHandler(object sender, TransportStreamEventArgs args);

    //    [DataContract]
    public class PidMetric : Telemetry.Metrics.Metric
    {

        private int _periodPacketCount = 0;
        private int _periodCcErrorCount = 0;
        private int _periodTeiCount = 0;
        private ulong _lastPcr = 0;
        private ulong _periodLargestPcrDelta;
        private int _periodLargestPcrDrift;
        private int _periodLowestPcrDrift;
        private int _largePcrDriftCount = 0;
        private const int PcrDriftLimit = 100;

        private ulong _referencePcr;
        private ulong _referenceTime;

        public PidMetric(int samplingPeriod = 5000)
        {
            SamplingPeriod = samplingPeriod;
        }

        protected override void ResetPeriodTimerCallback(object o)
        {
            lock (this)
            {
                PeriodPacketCount = _periodPacketCount;
                _periodPacketCount = 0;

                PeriodCcErrorCount = _periodCcErrorCount;
                _periodCcErrorCount = 0;

                PeriodTeiCount = _periodTeiCount;
                _periodTeiCount = 0;

                PeriodLargestPcrDelta = (int)new TimeSpan((long)(_periodLargestPcrDelta / 2.7)).TotalMilliseconds;

                _periodLargestPcrDelta = 0;

                PeriodLargestPcrDrift = _periodLargestPcrDrift;
                _periodLargestPcrDrift = 0;

                PeriodLowestPcrDrift = _periodLowestPcrDrift;
                _periodLowestPcrDrift = 0;


                base.ResetPeriodTimerCallback(o);
            }
        }

         
        public int Pid { get; set; }

         
        public long PacketCount { get; private set; }
        
         
        public int PeriodPacketCount { get; private set; }

        public long TeiCount { get; private set; }
        
        public int PeriodTeiCount { get; private set; }
        
        public long CcErrorCount { get; private set; }
        
        public int PeriodCcErrorCount { get; private set; }
        
        public bool HasPcr { get; } = false;
        
        public int PeriodLargestPcrDelta { get; private set; }
        
        public int PeriodLargestPcrDrift { get; private set; }
        
        public int PeriodLowestPcrDrift { get; private set; }

        private int LastCc { get; set; }
        
        public void AddPacket(TsPacket newPacket)
        {
            try
            {
                if (newPacket.Pid != Pid)
                    throw new InvalidOperationException("Cannot add TS Packet from different pid to a metric!");

                if (newPacket.TransportErrorIndicator)
                {
                    TeiCount++;
                    _periodTeiCount++;
                    OnTeiDetected(newPacket);
                }
                else
                {
                    CheckCcContinuity(newPacket);
                    CheckPcr(newPacket);
                    LastCc = newPacket.ContinuityCounter;
                }

                PacketCount++;
                _periodPacketCount++;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Exception generated within AddPacket method: " + ex.Message);
            }
        }

        private void CheckPcr(TsPacket tsPacket)
        {
            if (!tsPacket.AdaptationFieldExists) return;
            if (!tsPacket.AdaptationField.PcrFlag) return;
            if (tsPacket.AdaptationField.FieldSize < 1) return;

            if (tsPacket.AdaptationField.DiscontinuityIndicator)
            {
                Debug.WriteLine("Adaptation field discont indicator");
                return;
            }
            
            if (_lastPcr != 0)
            {
                var latestDelta = tsPacket.AdaptationField.Pcr - _lastPcr;
                if (latestDelta > _periodLargestPcrDelta) _periodLargestPcrDelta = latestDelta;

                var elapsedPcr = (long)(tsPacket.AdaptationField.Pcr - _referencePcr);
                var elapsedClock = (long)((DateTime.UtcNow.Ticks * 2.7) - _referenceTime);
                var drift = (int)(elapsedClock - elapsedPcr) / 27000;

                if (drift > _periodLargestPcrDrift)
                {
                    _periodLargestPcrDrift = drift;
                }

                if (drift > PcrDriftLimit)
                {
                    _largePcrDriftCount++;
                }

                drift = (int)(elapsedPcr - elapsedClock) / 27000;
                if (drift > _periodLowestPcrDrift)
                {
                    _periodLowestPcrDrift = drift;
                }

                if (drift > PcrDriftLimit)
                {
                    _largePcrDriftCount++;
                }
            }
            else
            {
                //first PCR value - set up reference values
                _referencePcr = tsPacket.AdaptationField.Pcr;
                _referenceTime = (ulong)(DateTime.UtcNow.Ticks*2.7);
            }

            if (_largePcrDriftCount > 5)
            {
                //exceeded PCR drift ceiling - reset clocks
                _referencePcr = tsPacket.AdaptationField.Pcr;
                _referenceTime = (ulong)(DateTime.UtcNow.Ticks * 2.7);
            }

            _lastPcr = tsPacket.AdaptationField.Pcr;
        }

        private void CheckCcContinuity(TsPacket newPacket)
        {
            try
            {
                if (PacketCount == 0)
                {
                    //fresh metric, first packet - so no possible error yet...
                    return;
                }

                if (newPacket.Pid == 0x1fff)
                    return;

                if (LastCc == newPacket.ContinuityCounter)
                {
                    //CC should only be expected to increase if data is present
                    //E.g. a pid used for PCR only may never increase CC
                    if (newPacket.ContainsPayload)
                    {
                        CcErrorCount++;
                        _periodCcErrorCount++;
                    }
                    
                    return;
                }

                if (LastCc != 15)
                {
                    if (LastCc + 1 != newPacket.ContinuityCounter)
                    {
                        CcErrorCount++;
                        _periodCcErrorCount++;
                        OnDiscontinuityDetected(newPacket);
                        return;
                    }
                }

                if (LastCc != 15 || newPacket.ContinuityCounter == 0) return;

                CcErrorCount++;
                _periodCcErrorCount++;
                OnDiscontinuityDetected(newPacket);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Exception generated within CheckCcContinuity method: " + ex.Message);
            }
        }

        // Continuity Counter Error has been detected.
        public event DiscontinuityDetectedEventHandler DiscontinuityDetected;
        
        private void OnDiscontinuityDetected(TsPacket tsPacket)
        {
            //reset reference PCR values used for drift check - set up reference values
            _referencePcr = tsPacket.AdaptationField.Pcr;
            _referenceTime = (ulong)(DateTime.UtcNow.Ticks * 2.7);

            var handler = DiscontinuityDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPacket.Pid };
            handler(this, args);
        }

        // Transport Error Indicator flag detected
        public event TransportErrorIndicatorDetectedEventHandler TeiDetected;

        private void OnTeiDetected(TsPacket tsPacket)
        {
            //reset reference PCR values used for drift check - set up reference values
            _referencePcr = tsPacket.AdaptationField.Pcr;
            _referenceTime = (ulong)(DateTime.UtcNow.Ticks * 2.7);

            var handler = TeiDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPacket.Pid };
            handler(this, args);
        }

    }
}
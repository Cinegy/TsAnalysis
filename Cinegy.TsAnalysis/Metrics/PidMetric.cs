/*   Copyright 2017-2023 Cinegy GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using System;
using System.Diagnostics;
using Cinegy.TsDecoder.TransportStream;
using System.Runtime.Serialization;

namespace Cinegy.TsAnalysis.Metrics
{
    public delegate void DiscontinuityDetectedEventHandler(object sender, TransportStreamEventArgs args);
    public delegate void TransportErrorIndicatorDetectedEventHandler(object sender, TransportStreamEventArgs args);

    [DataContract]
    public class PidMetric : Metric
    {
        private int _periodPacketCount;
        private int _periodCcErrorCount;
        private int _periodTeiCount;
        private ulong _lastPcr;
        private ulong _periodLargestPcrDelta;
        private float _periodLargestPcrDrift;
        private float _periodLowestPcrDrift;
        private int _largePcrDriftCount;
        private const int PcrDriftLimit = 2700000; //100ms in 27Mhz clock ticks
        private readonly double _conversionFactor27Mhz = 27000000.0 / Stopwatch.Frequency; //calculate platform conversion factor for timestamps

        private ulong _referencePcr;
        private double _referenceTime;
        private readonly DateTime _startTime = DateTime.UtcNow;

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

        public float PeriodLargestPcrDrift { get; private set; }

        public float PeriodLowestPcrDrift { get; private set; }

        private int LastCc { get; set; }

        public void AddPacket(TsPacket newPacket, long timestamp = -1)
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
                    CheckPcr(newPacket, timestamp);
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

        private void CheckPcr(TsPacket tsPacket, long timestamp)
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

                var elapsedClock = timestamp * _conversionFactor27Mhz - _referenceTime;

                var drift = (float)(elapsedClock - elapsedPcr) / 27000;

                if (drift > _periodLargestPcrDrift)
                {
                    _periodLargestPcrDrift = drift;
                }

                if (drift > PcrDriftLimit)
                {
                    _largePcrDriftCount++;
                }

                drift = (float)(elapsedPcr - elapsedClock) / 27000;
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

                //wait 10 seconds before sampling datum PCR time - otherwise everything drifts immediately as analyzer finishes launching tasks
                if (DateTime.UtcNow.Subtract(_startTime) < TimeSpan.FromSeconds(10)) return;
                ResetReferenceTime(tsPacket.AdaptationField.Pcr);
            }

            if (_largePcrDriftCount > 5)
            {
                //exceeded PCR drift ceiling - reset clocks
                ResetReferenceTime(tsPacket.AdaptationField.Pcr);
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
            ResetReferenceTime(0);

            var handler = DiscontinuityDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPacket.Pid };
            handler(this, args);
        }

        private void ResetReferenceTime(ulong newPcr)
        {
            _referencePcr = newPcr;
            _lastPcr = 0;

            if (newPcr == 0)
            {
                _referenceTime = 0;
                return;
            }

            _referenceTime =
                Stopwatch.GetTimestamp() * _conversionFactor27Mhz; //convert stamp to 27Mhz clock 
        }

        // Transport Error Indicator flag detected
        public event TransportErrorIndicatorDetectedEventHandler TeiDetected;

        private void OnTeiDetected(TsPacket tsPacket)
        {
            //reset reference PCR values used for drift check - set up reference values
            ResetReferenceTime(tsPacket.AdaptationField.Pcr);

            var handler = TeiDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPacket.Pid };
            handler(this, args);
        }

    }
}
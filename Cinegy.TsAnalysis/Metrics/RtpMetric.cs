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

namespace Cinegy.TsAnalysis.Metrics
{
    public class RtpMetric : Metric
    {
        private long _totalPackets;
        private int _periodEstimatedLostPackets;

        public RtpMetric(int samplingPeriod = 5000)
        {
            SamplingPeriod = samplingPeriod;
        }

        protected override void ResetPeriodTimerCallback(object o)
        {
            lock (this)
            {
                PeriodEstimatedLostPackets = _periodEstimatedLostPackets;
                _periodEstimatedLostPackets = 0;

                base.ResetPeriodTimerCallback(o);
            }
        }
        
        public long EstimatedLostPackets { get; private set; }
        
        public long PeriodEstimatedLostPackets { get; private set; }
        
        public int LastSequenceNumber { get; private set; }
        
        public uint Ssrc { get; private set; }
        
        public uint LastTimestamp { get; private set; }

        public void AddPacket(byte[] data)
        {
            var seqNum = (data[2] << 8) + data[3];
            LastTimestamp = (uint)((data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7]);
            Ssrc = (uint)((data[8] << 24) + (data[9] << 16) + (data[10] << 8) + data[11]);

            if (_totalPackets == 0)
            {
                RegisterFirstPacket(seqNum);
                return;
            }

            _totalPackets++;

            if (seqNum == 0)
            {
                if (LastSequenceNumber != ushort.MaxValue)
                {
                    var lost = ushort.MaxValue - LastSequenceNumber;
                    if (lost > 30000)
                    {
                        lost = 1;
                    }
                    EstimatedLostPackets += lost;
                    _periodEstimatedLostPackets += lost;

                    OnSequenceDiscontinuityDetected();
                }
            }
            else if (LastSequenceNumber + 1 != seqNum)
            {
                var seqDiff = seqNum - LastSequenceNumber;

                if (seqDiff < 0)
                {
                    seqDiff = seqNum + ushort.MaxValue - LastSequenceNumber;
                }
                if (seqDiff > 30000)
                {
                    seqDiff = 1;
                }
                EstimatedLostPackets += seqDiff;
                _periodEstimatedLostPackets += seqDiff;

                OnSequenceDiscontinuityDetected();
            }


            LastSequenceNumber = seqNum;
        }

        private void RegisterFirstPacket(int seqNum)
        {
            LastSequenceNumber = seqNum;
            _totalPackets++;
        }

        // Sequence Counter Error has been detected
        public event EventHandler SequenceDiscontinuityDetected;

        private void OnSequenceDiscontinuityDetected()
        {
            var handler = SequenceDiscontinuityDetected;
            handler?.Invoke(this, EventArgs.Empty);
        }
    }
}

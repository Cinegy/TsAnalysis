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
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace Cinegy.TsAnalysis.Metrics
{
    public class NetworkMetric : Metric
    {
        private bool _averagesReady;
        private bool _bufferOverflow;
        private long _currentPacketTime;
        private long _currentSampleTime;
        private int _currentSecond;
        private long _dataThisSecond;
        private long _lastPacketTime;
        private int _packetsThisSecond;

        private int _currentPeriodPackets;
        private double _periodLongestTimeBetweenPackets;
        private double _periodShortestTimeBetweenPackets;
        private float _periodMaxBufferUsage;
        private int _periodData;
        private int _periodMaxPacketQueue;
        private readonly long _stopwatchFrequency = Stopwatch.Frequency;

        protected override void ResetPeriodTimerCallback(object o)
        {
            lock (this)
            {
                PeriodPackets = _currentPeriodPackets;
                _currentPeriodPackets = 0;

                PeriodLongestTimeBetweenPackets = _periodLongestTimeBetweenPackets;
                _periodLongestTimeBetweenPackets = 0;

                PeriodShortestTimeBetweenPackets = _periodShortestTimeBetweenPackets;
                _periodShortestTimeBetweenPackets = 0;

                PeriodMaxNetworkBufferUsage = _periodMaxBufferUsage;
                _periodMaxBufferUsage = 0;

                PeriodData = _periodData;
                _periodData = 0;

                PeriodMaxPacketQueue = _periodMaxPacketQueue;
                _periodMaxPacketQueue = 0;

                base.ResetPeriodTimerCallback(o);

            }
        }

        /// <summary>
        /// The multicast address that is associated with this metric
        /// </summary>
        public string MulticastAddress { get; set; }

        /// <summary>
        /// The multicast group that is associated with this metric
        /// </summary>
        public int MulticastGroup { get; set; }

        /// <summary>
        /// All time total of packets received (unless explicitly reset)
        /// </summary>
        public long TotalPackets { get; private set; }

        /// <summary>
        /// Total of packets received within the last complete sampling period
        /// </summary>
        public long PeriodPackets { get; private set; }

        /// <summary>
        /// Total data volume sum of all packets received (unless explicitly reset)
        /// </summary>
        public long TotalData { get; private set; }

        /// <summary>
        /// Total data volume sum of all packets received within the last complete sampling period
        /// </summary>
        public long PeriodData { get; private set; }

        /// <summary>
        /// Instantaneous bitrate, sampled over the last complete second
        /// </summary>
        public long CurrentBitrate { get; private set; }

        /// <summary>
        /// Highest per-second bitrate measured since start (unless explicitly reset)
        /// </summary>
        public long HighestBitrate { get; private set; }

        //TODO: This
        /// <summary>
        /// Highest per-second bitrate measured within the last complete sampling period
        /// </summary>
        // 
        //public long PeriodHighestBitrate { get; private set; }

        /// <summary>
        /// Lowest per-second bitrate measured since start (unless explicitly reset)
        /// </summary>
        public long LowestBitrate { get; private set; } = 999999999;

        ////TODO: This
        ///// <summary>
        ///// Lowest per-second bitrate measured within the last complete sampling period
        ///// </summary>
        // 
        //public long PeriodLowestBitrate { get; private set; }

        /// <summary>
        /// All-time average bitrate measured since start (unless explicitly reset)
        /// </summary>
        public long AverageBitrate => (long)(TotalData / DateTime.UtcNow.Subtract(StartTime).TotalSeconds) * 8;

        /// <summary>
        /// Average bitrate measured within the last complete sampling period
        /// </summary>
        public long PeriodAverageBitrate => (PeriodData / (SamplingPeriod / 1000)) * 8;

        /// <summary>
        /// Packets received within the last complete second
        /// </summary>
        public int PacketsPerSecond { get; private set; }

        /// <summary>
        /// Current level of network buffer usage.
        /// A high value indicates TS Analyser is unable to keep up with the inbound rate and may not account for all packets under overflow conditions
        /// </summary>
        public float NetworkBufferUsage
        {
            get
            {
                if (UdpClient == null) return -1;
                float avail = UdpClient.Available;
                return avail / UdpClient.Client.ReceiveBufferSize * 100;
            }
        }

        /// <summary>
        /// The highest network buffer usage since since start (unless explicitly reset)
        /// </summary>
        public float MaxNetworkBufferUsage { get; private set; }

        /// <summary>
        /// The highest network buffer usage within the last sampling period
        /// </summary>
        public float PeriodMaxNetworkBufferUsage { get; private set; }

        /// <summary>
        /// Instantaneous time between last two received packets
        /// </summary>
        public double TimeBetweenLastPacket { get; private set; }

        /// <summary>
        /// All-time longest time between two received packets (unless explicitly reset)
        /// </summary>
        public double LongestTimeBetweenPackets { get; private set; }

        /// <summary>
        /// Longest time between two received packets within the last sampling period
        /// </summary>
        public double PeriodLongestTimeBetweenPackets { get; private set; }

        /// <summary>
        /// All-time shortest time between two received packets (unless explicitly reset)
        /// </summary>
        public double ShortestTimeBetweenPackets { get; private set; }

        /// <summary>
        /// Shortest time between two received packets within the last sampling period
        /// </summary>
        public double PeriodShortestTimeBetweenPackets { get; private set; }

        ////TODO: This
        ///// <summary>
        ///// All-time average time between two received packets (unless explicitly reset)
        ///// </summary>
        // 
        //public float AverageTimeBetweenPackets { get; private set; }

        ////TODO: This
        ///// <summary>
        ///// Average time between two received packets within the last sampling period
        ///// </summary>
        // 
        //public float PeriodAverageTimeBetweenPackets { get; private set; }

        /// <summary>
        /// Current count of packets waiting in queue for processing
        /// </summary>
        public float CurrentPacketQueue { get; private set; }

        /// <summary>
        /// All-time maximum value for count of packets waiting in queue (unless explicitly reset)
        /// </summary>
        public float MaxPacketQueue { get; private set; }

        /// <summary>
        /// Maximum value for count of packets waiting in queue within the last sampling period
        /// </summary>
        public float PeriodMaxPacketQueue { get; private set; }

        [JsonIgnore]
        public UdpClient UdpClient { get; set; }

        public void AddPacket(int dataSize, long timestamp, int currentQueueSize)
        {
            lock (this)
            {
                if (TotalPackets == 0)
                {
                    RegisterFirstPacket();
                }

                CurrentPacketQueue = currentQueueSize;

                if (MaxPacketQueue < currentQueueSize) MaxPacketQueue = currentQueueSize;

                if (_periodMaxPacketQueue < currentQueueSize) _periodMaxPacketQueue = currentQueueSize;

                _currentPacketTime = timestamp;

                var timeBetweenLastPacket = (double)(_currentPacketTime - _lastPacketTime) / _stopwatchFrequency;

                TimeBetweenLastPacket = timeBetweenLastPacket;

                _lastPacketTime = _currentPacketTime;

                if (TotalPackets == 1)
                {
                    ShortestTimeBetweenPackets = TimeBetweenLastPacket;
                    _currentSecond = DateTime.UtcNow.Second;
                }

                if (TotalPackets > 10)
                {
                    if (TimeBetweenLastPacket > LongestTimeBetweenPackets)
                        LongestTimeBetweenPackets = TimeBetweenLastPacket;

                    if (TimeBetweenLastPacket > _periodLongestTimeBetweenPackets)
                        _periodLongestTimeBetweenPackets = TimeBetweenLastPacket;

                    if (TimeBetweenLastPacket < ShortestTimeBetweenPackets)
                        ShortestTimeBetweenPackets = TimeBetweenLastPacket;

                    if (DateTime.UtcNow.Second == _currentSecond)
                    {
                        _packetsThisSecond++;
                    }
                    else
                    {
                        PacketsPerSecond = _packetsThisSecond;
                        _packetsThisSecond = 1;
                        _currentSecond = DateTime.UtcNow.Second;
                    }
                }

                TotalPackets++;
                _currentPeriodPackets++;
                TotalData += dataSize;
                _periodData += dataSize;

                if (Stopwatch.GetTimestamp() - _currentSampleTime < _stopwatchFrequency)
                {
                    _dataThisSecond += dataSize;
                }
                else
                {
                    if (!_averagesReady & (DateTime.UtcNow.Subtract(StartTime).TotalMilliseconds > 1000))
                        _averagesReady = true;

                    if (_averagesReady)
                    {
                        CurrentBitrate = _dataThisSecond * 8;
                        if (CurrentBitrate > HighestBitrate) HighestBitrate = CurrentBitrate;
                        if (CurrentBitrate < LowestBitrate) LowestBitrate = CurrentBitrate;

                        _dataThisSecond = 0;
                        _currentSampleTime = Stopwatch.GetTimestamp();
                    }
                }

                var buffVal = NetworkBufferUsage;

                if (buffVal > _periodMaxBufferUsage)
                {
                    _periodMaxBufferUsage = buffVal;
                }

                if (buffVal > MaxNetworkBufferUsage)
                {
                    MaxNetworkBufferUsage = buffVal;
                }

                if (buffVal > 99)
                {
                    OnBufferOverflow();
                }
                else
                {
                    _bufferOverflow = false;
                }
            }
        }

        private void RegisterFirstPacket()
        {
            StartTime = DateTime.UtcNow;
            _currentSampleTime = Stopwatch.GetTimestamp();
            _lastPacketTime = _currentSampleTime;
        }

        public event EventHandler BufferOverflow;

        protected virtual void OnBufferOverflow()
        {
            var handler = BufferOverflow;
            if (_bufferOverflow) return;
            handler?.Invoke(this, EventArgs.Empty);
            _bufferOverflow = true;
        }
    }

}
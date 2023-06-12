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
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Threading;
using Cinegy.TsAnalysis.Logging;
using Cinegy.TsAnalysis.Metrics;
using Cinegy.TsDecoder.Buffers;
using Cinegy.TsDecoder.TransportStream;
using Microsoft.Extensions.Logging;

namespace Cinegy.TsAnalysis
{
    public class Analyzer : IDisposable
    {
        private readonly Meter tsAnalysisMeter = new Meter("Cinegy.TsAnalysis");
        private readonly Counter<long> tsPktCounter;
        private readonly Counter<long> corruptedUdpPkts;
        private readonly ObservableGauge<long> lastPcrGauge;
        private readonly Counter<long> pidCounters;
        private readonly Counter<long> pidCcCounters;

        private readonly Dictionary<int, KeyValuePair<string, object>> _pidLabelCacheDictionary = new();

        public delegate void TsMetricLogRecordReadyEventHandler(object sender, TsMetricLogRecordReadyEventHandlerArgs args);

        // ReSharper disable once NotAccessedField.Local
        private Timer _periodicDataTimer;
        private Thread _processQueueWorkerThread;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _pendingExit;
        private readonly ILogger _logger;
        private bool _disposedValue;

        public DateTime StartTime { get; private set; }

        public RingBuffer RingBuffer { get; } = new(5000,1500,true);
        
        public bool HasRtpHeaders { get; set; } = false;

        public bool InspectTsPackets { get; set; } = true;
        
        public ushort SelectedProgramNumber { get; set; }

        public bool VerboseLogging { get; set; }

        /// <summary>
        /// Sampling period of aggregated analytics in milliseconds
        /// </summary>
        public int SamplingPeriod { get; set; } = 5000;

        public NetworkMetric NetworkMetric { get; private set; }

        public RtpMetric RtpMetric { get; private set; }

        public List<PidMetric> PidMetrics { get; private set; } = new List<PidMetric>();

        //public Logger Logger
        //{
        //    get => _logger ?? (_logger = LogManager.CreateNullLogger());
        //    set => _logger = value;
        //}

        public ulong LastPcr { get; set; }

        public ulong LastOpcr { get; set; }
        
        public TsDecoder.TransportStream.TsDecoder TsDecoder { get;set; } = new();

        public int SelectedPcrPid { get; set; }

        public Analyzer(ILogger logger = null)
        {
            _logger = logger;

            tsPktCounter = tsAnalysisMeter.CreateCounter<long>("tsPackets");
            lastPcrGauge = tsAnalysisMeter.CreateObservableGauge<long>("lastPcr", () => (long)(LastPcr / 2.7));
            pidCounters = tsAnalysisMeter.CreateCounter<long>("pidCount");
            pidCcCounters = tsAnalysisMeter.CreateCounter<long>("pidCcCount");
            corruptedUdpPkts = tsAnalysisMeter.CreateCounter<long>("corruptedUdpPackets");
        }

        public void Setup(string multicastAddress = "", int multicastPort = 0)
        {
            _cancellationTokenSource = new CancellationTokenSource();

            _periodicDataTimer = new Timer(UpdateSeriesDataTimerCallback, null, 0, SamplingPeriod);

            SetupMetricsAndDecoders(multicastAddress, multicastPort);

            _processQueueWorkerThread = new Thread(ProcessQueueWorkerThread);

            _processQueueWorkerThread.Start();            
        }
        
        public void AnalyzePackets(TsPacket[] tsPackets, long timestamp = -1, int packetCount = 0)
        {
            if (timestamp == -1)
            {
                timestamp = Stopwatch.GetTimestamp();
            }

            if (packetCount == 0) packetCount = tsPackets.Length;

            tsPktCounter.Add(packetCount);
            
            lock (PidMetrics)
            {
                for (var i = 0; i < packetCount; i++)
                {
                    var tsPacket = tsPackets[i];
                    if (!_pidLabelCacheDictionary.ContainsKey(tsPacket.Pid))
                    {
                        _pidLabelCacheDictionary.Add(tsPacket.Pid,new KeyValuePair<string, object>("pid", tsPacket.Pid));
                    }

                    pidCounters?.Add(1, _pidLabelCacheDictionary[tsPacket.Pid]);

                    if (tsPacket.AdaptationFieldExists)
                    {
                        if (tsPacket.AdaptationField.PcrFlag)
                        {
                            if (SelectedPcrPid != 0)
                            {
                                if (tsPacket.Pid == SelectedPcrPid)
                                    LastPcr = tsPacket.AdaptationField.Pcr;
                            }
                            else
                            {
                                LastPcr = tsPacket.AdaptationField.Pcr;
                            }
                        }

                        if (tsPacket.AdaptationField.OpcrFlag)
                        {
                            if (SelectedPcrPid != 0)
                            {
                                if (tsPacket.Pid == SelectedPcrPid)
                                    LastOpcr = tsPacket.AdaptationField.Opcr;
                            }
                            else
                            {
                                LastOpcr = tsPacket.AdaptationField.Opcr;
                            }
                        }
                    }
                    
                    PidMetric currentPidMetric = null;
                    foreach (var pidMetric in PidMetrics)
                    {
                        if (pidMetric.Pid != tsPacket.Pid) continue;
                        currentPidMetric = pidMetric;
                        break; 
                    }

                    if (currentPidMetric == null)
                    {
                        currentPidMetric = new PidMetric(SamplingPeriod) { Pid = tsPacket.Pid };
                        currentPidMetric.DiscontinuityDetected += CurrentPidMetric_DiscontinuityDetected;
                        currentPidMetric.TeiDetected += CurrentPidMetric_TeiDetected;
                        PidMetrics.Add(currentPidMetric);
                    }

                    currentPidMetric.AddPacket(tsPacket, timestamp);

                    if (TsDecoder == null) continue;
                    lock (TsDecoder)
                    {
                        TsDecoder.AddPacket(tsPacket);
                    }
                }
            }
        }

        private void UpdateSeriesDataTimerCallback(object o)
        {
            try
            {
                var tsMetricLogRecord = new TsMetricLogRecord()
                {
                    Net = NetworkMetric
                };


                if (HasRtpHeaders)
                {
                    tsMetricLogRecord.Rtp = RtpMetric;
                }

                var tsMetric = new TsMetric();

                foreach (var pidMetric in PidMetrics)
                {
                    tsMetric.PidCount++;
                    tsMetric.PidPackets += pidMetric.PeriodPacketCount;
                    tsMetric.PidCcErrors += pidMetric.PeriodCcErrorCount;
                    tsMetric.TeiErrors += pidMetric.PeriodTeiCount;

                    if (tsMetric.LongestPcrDelta < pidMetric.PeriodLargestPcrDelta)
                    {
                        tsMetric.LongestPcrDelta = pidMetric.PeriodLargestPcrDelta;
                    }

                    if (tsMetric.LargestPcrDrift < pidMetric.PeriodLargestPcrDrift)
                    {
                        tsMetric.LargestPcrDrift = pidMetric.PeriodLargestPcrDrift;
                    }

                    if (tsMetric.LowestPcrDrift < pidMetric.PeriodLowestPcrDrift)
                    {
                        tsMetric.LowestPcrDrift = pidMetric.PeriodLowestPcrDrift;
                    }
                }

                tsMetricLogRecord.Ts = tsMetric;

                //LogEventInfo lei = new TelemetryLogEventInfo
                //{
                //    Key = "TSD",
                //    TelemetryObject = tsMetricLogRecord,
                //    Level = LogLevel.Info
                //};

                //Logger.Log(lei);


                var handler = TsMetricLogRecordReady;
                if (_pendingExit) return;
                handler?.BeginInvoke(this, new TsMetricLogRecordReadyEventHandlerArgs { LogRecord = tsMetricLogRecord }, null, null);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Problem generating time-slice log record: {ex.Message}");
                throw;
            }
        }

        private void SetupMetricsAndDecoders(string multicastAddress, int multicastPort)
        {
            if (!string.IsNullOrWhiteSpace(multicastAddress))
            {
                _logger?.LogInformation($@"Setting up TS Analyzer for UDP network capture on {multicastAddress}:{multicastPort}");
            }

            lock (PidMetrics)
            {
                StartTime = DateTime.UtcNow;

                NetworkMetric = new NetworkMetric()
                {
                    MulticastAddress = multicastAddress,
                    MulticastGroup = multicastPort,
                    SamplingPeriod = SamplingPeriod
                };

                NetworkMetric.BufferOverflow += NetworkMetric_BufferOverflow;

                RtpMetric = new RtpMetric(SamplingPeriod);

                RtpMetric.SequenceDiscontinuityDetected += RtpMetric_SequenceDiscontinuityDetected;

                PidMetrics = new List<PidMetric>();

                if (InspectTsPackets)
                {
                    TsDecoder = new TsDecoder.TransportStream.TsDecoder();
                    TsDecoder.TableChangeDetected += _tsDecoder_TableChangeDetected;
                }

            }
        }

        private void ProcessQueueWorkerThread()
        {
            var dataBuffer = new byte[12 + (188 * 7)];
            var factory = new TsPacketFactory();

            while (_pendingExit != true)
            {
                var capacity = RingBuffer.Remove(dataBuffer, out var dataSize, out var timestamp, _cancellationTokenSource.Token);

                if (capacity > 0)
                {
                    dataBuffer = new byte[capacity];
                    continue;
                }
                
                if (dataBuffer.Length != dataSize)
                {
                    //need to trim down buffer
                    var tmpArry = new byte[dataSize];
                    Buffer.BlockCopy(dataBuffer, 0, tmpArry, 0, dataSize);
                    dataBuffer = tmpArry;
                }

                //TODO: Re-implement support for historical buffer dumping
                try
                {
                    lock (NetworkMetric)
                    {
                        NetworkMetric.AddPacket(dataSize, (long)timestamp, RingBuffer.BufferFullness);

                        if (HasRtpHeaders)
                        {
                            RtpMetric.AddPacket(dataBuffer);
                        }

                        try
                        {
                            var tsPackets = factory.GetRentedTsPacketsFromData(dataBuffer,out var tsPktCount, dataSize);

                            if (tsPackets == null)
                            {
                                corruptedUdpPkts.Add(1);
                                continue;
                            }
                           
                            AnalyzePackets(tsPackets,(long)timestamp, tsPktCount);
                           
                            factory.ReturnTsPackets(tsPackets, tsPktCount);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogError($"Exception processing TS packet: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError($@"Unhandled exception within network receiver: {ex.Message}");
                }
            }

            LogMessage("Stopping analysis thread due to exit request.");
        }
        
        private void LogMessage(string message)
        {
            //var lei = new TelemetryLogEventInfo
            //{
            //    Level = LogLevel.Info,
            //    Key = "GenericEvent",
            //    Message = message
            //};

            //Logger.Log(lei);
            //_logger.LogInformation(message);
        }

        private void RtpMetric_SequenceDiscontinuityDetected(object sender, EventArgs e)
        {
            if (VerboseLogging)
            {
                //Logger.Log(new TelemetryLogEventInfo
                //{
                //    Message = "Discontinuity in RTP sequence",
                //    Level = LogLevel.Warn,
                //    Key = "Discontinuity"
                //});
            }
        }

        private void NetworkMetric_BufferOverflow(object sender, EventArgs e)
        {
            //Logger.Log(new TelemetryLogEventInfo
            //{
            //    Message = "Network buffer > 99% - probably loss of data from overflow",
            //    Level = LogLevel.Error,
            //    Key = "Overflow"
            //});
        }

        private void CurrentPidMetric_DiscontinuityDetected(object sender, TransportStreamEventArgs e)
        {
            OnDiscontinuityDetected(e.TsPid);
            
            pidCcCounters?.Add(1, new KeyValuePair<string, object>("pid", e.TsPid));

            if (VerboseLogging)
            {
                //Logger.Log(new TelemetryLogEventInfo()
                //{
                //    Message = "Discontinuity on TS PID {e.TsPid}",
                //    Level = LogLevel.Info,
                //    Key = "Discontinuity"
                //});
            }
        }
        
        private void CurrentPidMetric_TeiDetected(object sender, TransportStreamEventArgs args)
        {
            OnTeiDetected(args.TsPid);

            if (VerboseLogging)
            {
                //Logger.Log(new TelemetryLogEventInfo()
                //{
                //    Message = "Transport Error Indicator on TS PID {e.TsPid}",
                //    Level = LogLevel.Info,
                //    Key = "Transport Error Indicator"
                //});
            }
        }

        private void _tsDecoder_TableChangeDetected(object sender, TableChangedEventArgs e)
        {
            //only log PAT / PMT / SDT changes, otherwise we bomb the telemetry system with EPG and NIT updates
            if ((e.TableType == TableType.Pat) || (e.TableType == TableType.Pmt) || (e.TableType == TableType.Sdt))
            {
                //Logger.Log(new TelemetryLogEventInfo
                //{
                //    Message = "Table Change: " + e.Message,
                //    Level = LogLevel.Info,
                //    Key = "TableChange"
                //});
            }
        }

        public event TsMetricLogRecordReadyEventHandler TsMetricLogRecordReady;
        
        // Continuity Counter Error has been detected.
        public event DiscontinuityDetectedEventHandler DiscontinuityDetected;

        private void OnDiscontinuityDetected(int tsPid)
        {
            var handler = DiscontinuityDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPid };
            handler(this, args);
        }

        // Transport Error Indicator flag detected
        public event TransportErrorIndicatorDetectedEventHandler TeiDetected;

        private void OnTeiDetected(int tsPid)
        {
            var handler = TeiDetected;
            if (handler == null) return;
            var args = new TransportStreamEventArgs { TsPid = tsPid };
            handler(this, args);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _pendingExit = true;
                    _cancellationTokenSource.Cancel();
                    _periodicDataTimer.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

/*   Copyright 2017-2020 Cinegy GmbH

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
using System.Threading;
using Cinegy.Telemetry;
using Cinegy.TsAnalysis.Logging;
using Cinegy.TsAnalysis.Metrics;
using Cinegy.TtxDecoder.Teletext;
using NLog;
using Cinegy.TsDecoder.Buffers;
using Cinegy.TsDecoder.TransportStream;

namespace Cinegy.TsAnalysis
{
    public class Analyzer
    {
        public delegate void TsMetricLogRecordReadyEventHandler(object sender, TsMetricLogRecordReadyEventHandlerArgs args);

        // ReSharper disable once NotAccessedField.Local
        private Timer _periodicDataTimer;
        private bool _pendingExit;
        private Logger _logger;

        public TeletextDecoder TeletextDecoder { get; set; }

        public DateTime StartTime { get; private set; }

        public RingBuffer RingBuffer { get; } = new RingBuffer();
        
        public bool HasRtpHeaders { get; set; } = true;

        public bool InspectTsPackets { get; set; } = true;

        public bool InspectTeletext { get; set; }

        public ushort SelectedProgramNumber { get; set; }

        public bool VerboseLogging { get; set; }

        /// <summary>
        /// Sampling period of aggregated analytics in milliseconds
        /// </summary>
        public int SamplingPeriod { get; set; } = 5000;

        public NetworkMetric NetworkMetric { get; private set; }

        public RtpMetric RtpMetric { get; private set; }

        public List<PidMetric> PidMetrics { get; private set; } = new List<PidMetric>();

        public TeletextMetric TeletextMetric { get; private set; }

        public Logger Logger {
            get => _logger ?? (_logger = LogManager.CreateNullLogger());
            set => _logger = value;
        }

        public ulong LastPcr { get ; set ; }

        public ulong LastVidPts { get; set; }
        public ulong LastSubPts { get; set; }

        public TsDecoder.TransportStream.TsDecoder TsDecoder { get;set; } = new TsDecoder.TransportStream.TsDecoder();

        public int SelectedPcrPid { get; set; }

        public Analyzer()
        {
        }

        public Analyzer(Logger logger)
        {
            Logger = logger;
        }

        public void Setup(string multicastAddress = "", int multicastPort = 0)
        {
            _periodicDataTimer = new Timer(UpdateSeriesDataTimerCallback, null, 0, SamplingPeriod);

            SetupMetricsAndDecoders(multicastAddress, multicastPort);

            var queueThread = new Thread(ProcessQueueWorkerThread);

            queueThread.Start();
            
        }


        public void AnalyzePackets(IEnumerable<TsPacket> tsPackets)
        {
            lock (PidMetrics)
            {
                foreach (var tsPacket in tsPackets)
                {
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
                    }

                    if (tsPacket.PesHeader.Pts > 0)
                    {
                        if (tsPacket.Pid == 4096)
                        {
                            LastVidPts = (ulong)tsPacket.PesHeader.Pts;
                        }

                        if (tsPacket.Pid == 2049)
                        {
                            LastSubPts = (ulong)tsPacket.PesHeader.Pts;
                        }
                        /*
                        if (SelectedPcrPid != 0)
                        {
                            if (tsPacket.Pid == SelectedPcrPid)
                                LastPts = (ulong)tsPacket.PesHeader.Pts;
                        }
                        else
                        {
                            LastPts = (ulong)tsPacket.PesHeader.Pts;
                        }*/
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

                    currentPidMetric.AddPacket(tsPacket);



                    if (TsDecoder == null) continue;
                    lock (TsDecoder)
                    {
                        TsDecoder.AddPacket(tsPacket);

                        if (TeletextDecoder == null) continue;
                        lock (TeletextDecoder)
                        {
                            TeletextDecoder.AddPacket(tsPacket, TsDecoder);
                        }
                    }
                }
            }
        }

        public void Cancel()
        {
            _pendingExit = true;
            _periodicDataTimer.Dispose();
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

                var tsmetric = new TsMetric();

                foreach (var pidMetric in PidMetrics)
                {
                    tsmetric.PidCount++;
                    tsmetric.PidPackets += pidMetric.PeriodPacketCount;
                    tsmetric.PidCcErrors += pidMetric.PeriodCcErrorCount;
                    tsmetric.TeiErrors += pidMetric.PeriodTeiCount;

                    if (tsmetric.LongestPcrDelta < pidMetric.PeriodLargestPcrDelta)
                    {
                        tsmetric.LongestPcrDelta = pidMetric.PeriodLargestPcrDelta;
                    }

                    if (tsmetric.LargestPcrDrift < pidMetric.PeriodLargestPcrDrift)
                    {
                        tsmetric.LargestPcrDrift = pidMetric.PeriodLargestPcrDrift;
                    }

                    if (tsmetric.LowestPcrDrift < pidMetric.PeriodLowestPcrDrift)
                    {
                        tsmetric.LowestPcrDrift = pidMetric.PeriodLowestPcrDrift;
                    }
                }

                tsMetricLogRecord.Ts = tsmetric;

                LogEventInfo lei = new TelemetryLogEventInfo
                {
                    Key = "TSD",
                    TelemetryObject = tsMetricLogRecord,
                    Level = LogLevel.Info
                };

                Logger.Log(lei);


                var handler = TsMetricLogRecordReady;
                if (_pendingExit) return;
                handler?.BeginInvoke(this, new TsMetricLogRecordReadyEventHandlerArgs {  LogRecord = tsMetricLogRecord },null,null);
            }
            catch (Exception ex)
            {
                Logger.Error($"Problem generating time-slice log record: {ex.Message}");
                throw;
            }

        }

        private void SetupMetricsAndDecoders(string multicastAddress, int multicastPort)
        {
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

                if (InspectTeletext)
                {
                    TeletextDecoder = SelectedProgramNumber > 1
                        ? new TeletextDecoder(SelectedProgramNumber)
                        : new TeletextDecoder();
                    
                    TeletextMetric = new TeletextMetric(TeletextDecoder.Service);
                    TeletextDecoder.Service.TeletextPacketsReady += Service_TeletextPacketsReady;
                }


            }
        }

        private void Service_TeletextPacketsReady(object sender, TeletextPacketsReadyEventArgs e)
        {
            TeletextMetric?.AddPackets(e.Packets);
        }

        private void ProcessQueueWorkerThread()
        {
            var dataBuffer = new byte[12 + (188 * 7)];
            var factory = new TsPacketFactory();

            while (_pendingExit != true)
            {
                var capacity = RingBuffer.Remove(ref dataBuffer, out var dataSize, out var timestamp);

                if (capacity > 0)
                {
                    dataBuffer = new byte[capacity];
                    continue;
                }

                if (dataBuffer == null) continue;

                if (dataBuffer.Length != dataSize)
                {
                    //need to trim down buffer
                    var tmpArry = new byte[dataSize];
                    Buffer.BlockCopy(dataBuffer, 0, tmpArry, 0, dataSize);
                    dataBuffer = tmpArry;
                }

                //TODO: Reimplement support for historical buffer dumping

                try
                {
                    lock (NetworkMetric)
                    {
                        NetworkMetric.AddPacket(dataBuffer, (long)timestamp, RingBuffer.BufferFullness);

                        if (HasRtpHeaders)
                        {
                            RtpMetric.AddPacket(dataBuffer);
                        }
                        
                        try
                        {
                            var tsPackets = factory.GetTsPacketsFromData(dataBuffer);

                            if (tsPackets == null)
                            {
                                Logger.Log(new TelemetryLogEventInfo() { Message = "Packet received with no detected TS packets", Level = LogLevel.Info, Key = "Packet" });
                                continue;
                            }

                            AnalyzePackets(tsPackets);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log(new TelemetryLogEventInfo() { Message = $"Exception processing TS packet: {ex.Message}", Key = "Packet", Level = LogLevel.Warn });
                        }


                    }
                }
                catch (Exception ex)
                {
                    LogMessage($@"Unhandled exception within network receiver: {ex.Message}");
                }
            }

            LogMessage("Stopping analysis thread due to exit request.");
        }
        
        private void LogMessage(string message)
        {
            var lei = new TelemetryLogEventInfo
            {
                Level = LogLevel.Info,
                Key = "GenericEvent",
                Message = message
            };

            Logger.Log(lei);
        }

        private void RtpMetric_SequenceDiscontinuityDetected(object sender, EventArgs e)
        {
            if (VerboseLogging)
            {
                Logger.Log(new TelemetryLogEventInfo
                {
                    Message = "Discontinuity in RTP sequence",
                    Level = LogLevel.Warn,
                    Key = "Discontinuity"
                });
            }
        }

        private void NetworkMetric_BufferOverflow(object sender, EventArgs e)
        {
            Logger.Log(new TelemetryLogEventInfo
            {
                Message = "Network buffer > 99% - probably loss of data from overflow",
                Level = LogLevel.Error,
                Key = "Overflow"
            });
        }

        private void CurrentPidMetric_DiscontinuityDetected(object sender, TransportStreamEventArgs e)
        {
            OnDiscontinuityDetected(e.TsPid);

            if (VerboseLogging)
            {
                Logger.Log(new TelemetryLogEventInfo()
                {
                    Message = "Discontinuity on TS PID {e.TsPid}",
                    Level = LogLevel.Info,
                    Key = "Discontinuity"
                });
            }
        }
        
        private void CurrentPidMetric_TeiDetected(object sender, TransportStreamEventArgs args)
        {
            OnTeiDetected(args.TsPid);

            if (VerboseLogging)
            {
                Logger.Log(new TelemetryLogEventInfo()
                {
                    Message = "Transport Error Indicator on TS PID {e.TsPid}",
                    Level = LogLevel.Info,
                    Key = "Transport Error Indicator"
                });
            }
        }

        private void _tsDecoder_TableChangeDetected(object sender, TableChangedEventArgs e)
        {
            //only log PAT / PMT / SDT changes, otherwise we bomb the telemetry system with EPG and NIT updates
            if ((e.TableType == TableType.Pat) || (e.TableType == TableType.Pmt) || (e.TableType == TableType.Sdt))
            {
                Logger.Log(new TelemetryLogEventInfo
                {
                    Message = "Table Change: " + e.Message,
                    Level = LogLevel.Info,
                    Key = "TableChange"
                });
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
        

    }

}

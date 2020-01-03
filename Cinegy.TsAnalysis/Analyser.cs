using System;
using System.Collections.Generic;
using Cinegy.TsDecoder.TransportStream;
using NLog;

namespace Cinegy.TsAnalysis
{
    [Obsolete("This class is has been renamed to 'Analyzer', and is now just a wrapper around this rename - please migrate.")]
    public class Analyser : Analyzer
    {
        [Obsolete("This method has been renamed to AnalyzePackets, and this method is now just a wrapper around this rename - please migrate")]
        public void AnalysePackets(IEnumerable<TsPacket> tsPackets){
            AnalyzePackets(tsPackets);
        }

        public Analyser()
        {
        }

        public Analyser(Logger logger)
        {
            Logger = logger;
        }
    }
}
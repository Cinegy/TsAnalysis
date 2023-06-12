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

namespace Cinegy.TsAnalysis.Metrics
{
    public class TsMetric
    {

        public int PidCount { get; set; }


        public int PidPackets { get; set; }


        public int PidCcErrors { get; set; }


        public int TeiErrors { get; set; }


        public int LongestPcrDelta { get; set; }


        public float LargestPcrDrift { get; set; }


        public float LowestPcrDrift { get; set; }
    }
}

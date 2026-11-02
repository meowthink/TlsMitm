# Every mutation of Router/Siit.cs that RFC 7915's pins in tests/v6check are supposed to catch. The last
# field names the assertion each one is meant to turn red, so a case that builds green is a gap in the suite
# rather than a defect in the harness.
run_case M1-offset-shift  'fragmentOffset = fragmentWord >> 3;' 'fragmentOffset = fragmentWord >> 6;' 'Fragment Offset copy'
run_case M2-4884-octet    'type is 3 or 11 or 12 ? message[5] * 4' 'type is 3 or 11 or 12 ? message[6] * 4' 'RFC 4884 attribute'
run_case M3-ptb-plus-20   'Math.Min((long)reported + 20,' 'Math.Min((long)reported,' 'Packet Too Big 1420'
run_case M4-te-code       'case 3: shape = new Shape(11, code, true, -1, 0, false, guaranteed); return true;' 'case 3: shape = new Shape(11, 0, true, -1, 0, false, guaranteed); return true;' 'Time Exceeded code unchanged'
run_case M5-hop-undone    'result[8] = hopLimit;' 'result[8] = (byte)(hopLimit + 1);' 'Hop Limit decremented by the translator'
run_case M6-figure3-8     '            8 => 7,' '            8 => 6,' 'Figure 3 octet 8 row'
run_case M7-df-boundary   'Ipv4HeaderLength + bodyLength > Ipv4DfThreshold' 'Ipv4HeaderLength + bodyLength >= Ipv4DfThreshold' 'exactly-1260 DF cleared'
run_case M8-link-local    'IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal ||' 'IPAddress.IsLoopback(address) ||' 'fe80::1 source drop'
run_case M9a-v6-frag-icmp 'if (head.Fragmented)
            {
                why = "the ICMPv6 message sits behind' 'if (false)
            {
                why = "the ICMPv6 message sits behind' 'fragmented ICMPv6 refused'
run_case M9b-v4-frag-icmp 'if (head.Fragmented)
            {
                why = "the ICMPv4 message is a fragment' 'if (false)
            {
                why = "the ICMPv4 message is a fragment' 'fragmented ICMPv4 refused'
run_case M10-pseudo6-nh   'pseudo[39] = protocol;' 'pseudo[38] = protocol;' 'every v6 checksum'
run_case M11-map-swap     'mappedSource = MapOne(prefix, source);
            mappedDestination = MapOne(prefix, destination);' 'mappedSource = MapOne(prefix, destination);
            mappedDestination = MapOne(prefix, source);' 'addresses swapped: embedding + fold'

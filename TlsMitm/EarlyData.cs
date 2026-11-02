namespace TlsMitm;

/// <summary>
/// The records a 0-RTT client puts behind its ClientHello are the only thing that made such a session
/// look unterminable, so they are kept off the terminator and the session is terminated.
/// </summary>
public static class EarlyData
{
    /// <summary>
    /// Cuts a flight the caller already read off the client's socket into the hello record and the early
    /// records behind it. RFC 9846 §4.3.10 lets a client that supplies both the pre_shared_key and the
    /// early_data extensions "send Application Data in its first flight of messages", and §2.3's Figure 4
    /// shows where those records sit: protected under keys derived from a PSK this proxy does not hold.
    /// RFC 9846 Appendix E.4 puts the dummy change_cipher_spec in front of them, "immediately after the
    /// first ClientHello". Neither is something the handshake needs from here: §5.1 makes an
    /// application_data record always protected, so one a terminator cannot deprotect is one it fails on,
    /// and a change_cipher_spec is a record the peer has to drop in any case (RFC 9846 §5).
    ///
    /// With them withheld the handshake runs on without early data, and because no PSK was resolved the
    /// extension is not echoed - which is the case RFC 8470 §4 addresses: "If the server rejects early
    /// data at the TLS layer, a client MUST start sending again as though the connection were new". That
    /// copy arrives under the session's application keys, which the terminator does hold, and it is what
    /// the proxy reads.
    ///
    /// Only what is already in hand is withheld. A protected record carries outer content type 23 like
    /// every other one (RFC 9846 §5.2), so a filter that went on dropping that type would also drop the
    /// client's Finished and stall the handshake it was installed to enable; records that arrive after
    /// this flight are left for the terminator, which the embedded libssl is measured to answer with a
    /// ServerHello and no record-layer error. A hello that offers no early data, and one whose record the
    /// caller has not finished reading, comes back whole.
    /// </summary>
    public static (byte[] Hello, byte[] Early) Split(byte[] flight, bool clientOfferedEarlyData)
    {
        if (!clientOfferedEarlyData || flight.Length < 5) return (flight, Array.Empty<byte>());

        // RFC 9846 §5.1: the content type, the version this record claims, and the length of the octets
        // after those five - so the hello ends here whether or not the client sent anything behind it.
        var hello = 5 + ((flight[3] << 8) | flight[4]);
        return hello >= flight.Length ? (flight, Array.Empty<byte>()) : (flight[..hello], flight[hello..]);
    }
}

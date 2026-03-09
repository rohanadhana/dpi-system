package com.packetanalyzer.dpi.pcap;

import java.nio.ByteOrder;

public record PcapGlobalHeader(
    byte[] rawBytes,
    ByteOrder byteOrder,
    int snaplen,
    int network
) {
}

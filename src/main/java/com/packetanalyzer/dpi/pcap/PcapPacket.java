package com.packetanalyzer.dpi.pcap;

public record PcapPacket(
    long timestampSec,
    long timestampUsec,
    int originalLength,
    byte[] data
) {
}

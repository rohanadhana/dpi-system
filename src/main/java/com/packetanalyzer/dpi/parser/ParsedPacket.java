package com.packetanalyzer.dpi.parser;

import com.packetanalyzer.dpi.model.FiveTuple;

public record ParsedPacket(
    boolean valid,
    boolean hasIpv4,
    boolean hasTcp,
    boolean hasUdp,
    int protocol,
    int srcIp,
    int dstIp,
    String srcIpText,
    String dstIpText,
    int srcPort,
    int dstPort,
    int tcpFlags,
    int payloadOffset,
    int payloadLength,
    long timestampSec,
    long timestampUsec
) {
    public FiveTuple tuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}

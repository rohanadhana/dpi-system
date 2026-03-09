package com.packetanalyzer.dpi.parser;

import com.packetanalyzer.dpi.pcap.PcapPacket;

public final class PacketParser {
    private static final int ETH_LEN = 14;

    private PacketParser() {
    }

    public static ParsedPacket parse(PcapPacket packet) {
        byte[] data = packet.data();
        if (data.length < ETH_LEN) {
            return invalid(packet);
        }

        int etherType = u16(data, 12);
        if (etherType != 0x0800) {
            return invalid(packet);
        }

        int ipOffset = ETH_LEN;
        if (data.length < ipOffset + 20) {
            return invalid(packet);
        }

        int version = (data[ipOffset] >> 4) & 0x0f;
        if (version != 4) {
            return invalid(packet);
        }

        int ihl = data[ipOffset] & 0x0f;
        int ipHeaderLen = ihl * 4;
        if (ihl < 5 || data.length < ipOffset + ipHeaderLen) {
            return invalid(packet);
        }

        int protocol = data[ipOffset + 9] & 0xff;
        int srcIp = readIpv4Int(data, ipOffset + 12);
        int dstIp = readIpv4Int(data, ipOffset + 16);
        String srcIpText = toIpString(srcIp);
        String dstIpText = toIpString(dstIp);

        int transportOffset = ipOffset + ipHeaderLen;
        boolean hasTcp = false;
        boolean hasUdp = false;
        int srcPort = 0;
        int dstPort = 0;
        int tcpFlags = 0;
        int payloadOffset = transportOffset;

        if (protocol == 6) {
            hasTcp = true;
            if (data.length < transportOffset + 20) {
                return invalid(packet);
            }
            srcPort = u16(data, transportOffset);
            dstPort = u16(data, transportOffset + 2);
            int dataOffsetWords = (data[transportOffset + 12] >> 4) & 0x0f;
            int tcpLen = dataOffsetWords * 4;
            tcpFlags = data[transportOffset + 13] & 0xff;
            if (dataOffsetWords < 5 || data.length < transportOffset + tcpLen) {
                return invalid(packet);
            }
            payloadOffset = transportOffset + tcpLen;
        } else if (protocol == 17) {
            hasUdp = true;
            if (data.length < transportOffset + 8) {
                return invalid(packet);
            }
            srcPort = u16(data, transportOffset);
            dstPort = u16(data, transportOffset + 2);
            payloadOffset = transportOffset + 8;
        }

        int payloadLength = Math.max(0, data.length - payloadOffset);

        return new ParsedPacket(
            true,
            true,
            hasTcp,
            hasUdp,
            protocol,
            srcIp,
            dstIp,
            srcIpText,
            dstIpText,
            srcPort,
            dstPort,
            tcpFlags,
            payloadOffset,
            payloadLength,
            packet.timestampSec(),
            packet.timestampUsec()
        );
    }

    private static ParsedPacket invalid(PcapPacket packet) {
        return new ParsedPacket(false, false, false, false, 0, 0, 0,
            "", "", 0, 0, 0, 0, 0, packet.timestampSec(), packet.timestampUsec());
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static int readIpv4Int(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
            | ((data[offset + 1] & 0xff) << 16)
            | ((data[offset + 2] & 0xff) << 8)
            | (data[offset + 3] & 0xff);
    }

    public static String toIpString(int ip) {
        return ((ip >>> 24) & 0xff) + "." + ((ip >>> 16) & 0xff) + "." + ((ip >>> 8) & 0xff) + "." + (ip & 0xff);
    }

    public static int parseIp(String ip) {
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        int result = 0;
        for (String part : parts) {
            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 octet in: " + ip);
            }
            result = (result << 8) | octet;
        }
        return result;
    }
}

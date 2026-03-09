package com.packetanalyzer.dpi.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Optional;

public final class PcapReader implements Closeable {
    private final BufferedInputStream input;
    private final PcapGlobalHeader globalHeader;

    public PcapReader(Path path) throws IOException {
        this.input = new BufferedInputStream(new FileInputStream(path.toFile()));
        this.globalHeader = readGlobalHeader();
    }

    public PcapGlobalHeader globalHeader() {
        return globalHeader;
    }

    public Optional<PcapPacket> readNextPacket() throws IOException {
        byte[] packetHeader = input.readNBytes(16);
        if (packetHeader.length == 0) {
            return Optional.empty();
        }
        if (packetHeader.length < 16) {
            return Optional.empty();
        }

        ByteBuffer header = ByteBuffer.wrap(packetHeader).order(globalHeader.byteOrder());
        long tsSec = Integer.toUnsignedLong(header.getInt());
        long tsUsec = Integer.toUnsignedLong(header.getInt());
        int inclLen = header.getInt();
        int origLen = header.getInt();

        if (inclLen < 0 || inclLen > globalHeader.snaplen() || inclLen > 65535) {
            return Optional.empty();
        }

        byte[] data = input.readNBytes(inclLen);
        if (data.length < inclLen) {
            return Optional.empty();
        }

        return Optional.of(new PcapPacket(tsSec, tsUsec, origLen, data));
    }

    @Override
    public void close() throws IOException {
        input.close();
    }

    private PcapGlobalHeader readGlobalHeader() throws IOException {
        byte[] raw = input.readNBytes(24);
        if (raw.length < 24) {
            throw new IOException("Invalid PCAP: missing global header");
        }

        ByteOrder order = detectOrder(raw);
        ByteBuffer b = ByteBuffer.wrap(raw).order(order);
        b.getInt(); // magic
        b.getShort(); // major
        b.getShort(); // minor
        b.getInt(); // thiszone
        b.getInt(); // sigfigs
        int snaplen = b.getInt();
        int network = b.getInt();

        return new PcapGlobalHeader(raw, order, snaplen, network);
    }

    private ByteOrder detectOrder(byte[] raw) throws IOException {
        int b0 = raw[0] & 0xff;
        int b1 = raw[1] & 0xff;
        int b2 = raw[2] & 0xff;
        int b3 = raw[3] & 0xff;

        boolean littleMicro = b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1;
        boolean bigMicro = b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4;
        boolean littleNano = b0 == 0x4d && b1 == 0x3c && b2 == 0xb2 && b3 == 0xa1;
        boolean bigNano = b0 == 0xa1 && b1 == 0xb2 && b2 == 0x3c && b3 == 0x4d;

        if (littleMicro || littleNano) {
            return ByteOrder.LITTLE_ENDIAN;
        }
        if (bigMicro || bigNano) {
            return ByteOrder.BIG_ENDIAN;
        }
        throw new IOException("Unsupported PCAP magic number");
    }
}

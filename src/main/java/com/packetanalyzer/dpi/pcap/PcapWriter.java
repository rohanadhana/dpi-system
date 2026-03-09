package com.packetanalyzer.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;

public final class PcapWriter implements Closeable {
    private final BufferedOutputStream output;
    private final PcapGlobalHeader globalHeader;

    public PcapWriter(Path path, PcapGlobalHeader globalHeader) throws IOException {
        this.output = new BufferedOutputStream(new FileOutputStream(path.toFile()));
        this.globalHeader = globalHeader;
        this.output.write(globalHeader.rawBytes());
    }

    public void writePacket(PcapPacket packet) throws IOException {
        byte[] hdr = ByteBuffer.allocate(16)
            .order(globalHeader.byteOrder())
            .putInt((int) packet.timestampSec())
            .putInt((int) packet.timestampUsec())
            .putInt(packet.data().length)
            .putInt(packet.originalLength())
            .array();

        output.write(hdr);
        output.write(packet.data());
    }

    @Override
    public void close() throws IOException {
        output.flush();
        output.close();
    }
}

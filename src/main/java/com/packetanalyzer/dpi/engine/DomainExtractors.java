package com.packetanalyzer.dpi.engine;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public final class DomainExtractors {
    private DomainExtractors() {
    }

    public static Optional<String> extractTlsSni(byte[] payload) {
        if (payload.length < 9) {
            return Optional.empty();
        }

        if ((payload[0] & 0xff) != 0x16) {
            return Optional.empty();
        }

        int version = u16(payload, 1);
        if (version < 0x0300 || version > 0x0304) {
            return Optional.empty();
        }

        int recordLen = u16(payload, 3);
        if (recordLen > payload.length - 5) {
            return Optional.empty();
        }

        if ((payload[5] & 0xff) != 0x01) {
            return Optional.empty();
        }

        int offset = 5;
        offset += 4; // handshake header
        offset += 2; // client version
        offset += 32; // random
        if (offset >= payload.length) return Optional.empty();

        int sessionIdLen = payload[offset] & 0xff;
        offset += 1 + sessionIdLen;
        if (offset + 2 > payload.length) return Optional.empty();

        int cipherSuitesLen = u16(payload, offset);
        offset += 2 + cipherSuitesLen;
        if (offset >= payload.length) return Optional.empty();

        int compressionMethodsLen = payload[offset] & 0xff;
        offset += 1 + compressionMethodsLen;
        if (offset + 2 > payload.length) return Optional.empty();

        int extensionsLen = u16(payload, offset);
        offset += 2;

        int end = Math.min(payload.length, offset + extensionsLen);
        while (offset + 4 <= end) {
            int extType = u16(payload, offset);
            int extLen = u16(payload, offset + 2);
            offset += 4;
            if (offset + extLen > end) {
                break;
            }
            if (extType == 0x0000 && extLen >= 5) {
                int sniType = payload[offset + 2] & 0xff;
                int sniLen = u16(payload, offset + 3);
                if (sniType == 0x00 && sniLen <= extLen - 5 && offset + 5 + sniLen <= payload.length) {
                    String sni = new String(payload, offset + 5, sniLen, StandardCharsets.US_ASCII);
                    return Optional.of(sni.toLowerCase(Locale.ROOT));
                }
                break;
            }
            offset += extLen;
        }

        return Optional.empty();
    }

    public static Optional<String> extractHttpHost(byte[] payload) {
        if (payload.length < 4) {
            return Optional.empty();
        }

        String head = new String(payload, 0, Math.min(payload.length, 8192), StandardCharsets.US_ASCII);
        boolean isHttp = head.startsWith("GET ") || head.startsWith("POST") || head.startsWith("PUT ")
            || head.startsWith("HEAD") || head.startsWith("DELE") || head.startsWith("PATC") || head.startsWith("OPTI");
        if (!isHttp) {
            return Optional.empty();
        }

        String[] lines = head.split("\\r?\\n");
        for (String line : lines) {
            if (line.toLowerCase(Locale.ROOT).startsWith("host:")) {
                String value = line.substring(5).trim().toLowerCase(Locale.ROOT);
                int colon = value.indexOf(':');
                if (colon >= 0) {
                    value = value.substring(0, colon);
                }
                if (!value.isBlank()) {
                    return Optional.of(value);
                }
            }
        }
        return Optional.empty();
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }
}

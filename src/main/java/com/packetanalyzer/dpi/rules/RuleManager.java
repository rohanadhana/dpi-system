package com.packetanalyzer.dpi.rules;

import com.packetanalyzer.dpi.model.AppType;
import com.packetanalyzer.dpi.parser.PacketParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class RuleManager {
    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<Integer> blockedPorts = new HashSet<>();
    private final List<String> blockedDomains = new ArrayList<>();

    public void blockIp(String ip) {
        blockedIps.add(PacketParser.parseIp(ip));
    }

    public void blockApp(String appName) {
        AppType app = AppType.fromName(appName);
        if (app != AppType.UNKNOWN) {
            blockedApps.add(app);
        }
    }

    public void blockDomain(String domainPattern) {
        if (domainPattern != null && !domainPattern.isBlank()) {
            blockedDomains.add(domainPattern.trim().toLowerCase(Locale.ROOT));
        }
    }

    public void blockPort(int port) {
        blockedPorts.add(port);
    }

    public BlockResult shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (blockedIps.contains(srcIp)) {
            return BlockResult.blocked("IP", PacketParser.toIpString(srcIp));
        }
        if (blockedPorts.contains(dstPort)) {
            return BlockResult.blocked("PORT", Integer.toString(dstPort));
        }
        if (blockedApps.contains(app)) {
            return BlockResult.blocked("APP", app.displayName());
        }

        String normalized = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        for (String pattern : blockedDomains) {
            if (matchesDomain(normalized, pattern)) {
                return BlockResult.blocked("DOMAIN", pattern);
            }
        }

        return BlockResult.allowed();
    }

    public boolean loadFromFile(Path file) throws IOException {
        if (!Files.exists(file)) {
            return false;
        }

        String section = "";
        for (String rawLine : Files.readAllLines(file)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line;
                continue;
            }

            switch (section) {
                case "[BLOCKED_IPS]" -> blockIp(line);
                case "[BLOCKED_APPS]" -> blockApp(line);
                case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                default -> {
                }
            }
        }
        return true;
    }

    private boolean matchesDomain(String domain, String pattern) {
        if (domain.isEmpty()) {
            return false;
        }

        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            return domain.endsWith(suffix) || domain.equals(pattern.substring(2));
        }

        return domain.equals(pattern) || domain.contains(pattern);
    }

    public record BlockResult(boolean blocked, String type, String detail) {
        static BlockResult blocked(String type, String detail) {
            return new BlockResult(true, type, detail);
        }

        static BlockResult allowed() {
            return new BlockResult(false, "", "");
        }
    }
}

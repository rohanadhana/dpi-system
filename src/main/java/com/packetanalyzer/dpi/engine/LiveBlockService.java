package com.packetanalyzer.dpi.engine;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class LiveBlockService {
    private static final String START_PREFIX = "# DPI_BLOCK_START";
    private static final String END_PREFIX = "# DPI_BLOCK_END";
    private static final Map<String, List<String>> DOMAIN_GROUPS = buildDomainGroups();

    public void blockDomainsForDuration(List<String> domains, Duration duration) throws IOException, InterruptedException {
        if (domains == null || domains.isEmpty()) {
            throw new IllegalArgumentException("No domains provided for live blocking.");
        }
        if (duration.isZero() || duration.isNegative()) {
            throw new IllegalArgumentException("Duration must be positive.");
        }

        Path hostsFile = resolveHostsFile();
        String blockId = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plus(duration);

        List<String> existing = Files.readAllLines(hostsFile);
        List<String> clean = stripAllManagedBlocks(existing);

        List<String> blockSection = buildBlockSection(blockId, domains, expiresAt);
        List<String> updated = new ArrayList<>(clean);
        if (!updated.isEmpty() && !updated.get(updated.size() - 1).isBlank()) {
            updated.add("");
        }
        updated.addAll(blockSection);

        Files.write(hostsFile, updated);
        flushDnsCacheBestEffort();
        System.out.println("[LIVE BLOCK] Applied in hosts file: " + hostsFile);
        System.out.println("[LIVE BLOCK] Domains: " + String.join(", ", expandDomains(domains)));
        System.out.println("[LIVE BLOCK] Active until: " + expiresAt);

        try {
            TimeUnit.MILLISECONDS.sleep(duration.toMillis());
        } finally {
            removeBlockById(hostsFile, blockId);
            flushDnsCacheBestEffort();
            System.out.println("[LIVE BLOCK] Block expired and removed.");
        }
    }

    private Path resolveHostsFile() {
        String override = System.getenv("DPI_HOSTS_FILE");
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return Path.of("/etc/hosts");
    }

    private List<String> buildBlockSection(String blockId, List<String> domains, Instant expiresAt) {
        List<String> lines = new ArrayList<>();
        lines.add(START_PREFIX + " " + blockId + " expires=" + expiresAt);
        for (String d : expandDomains(domains)) {
            lines.add("127.0.0.1 " + d);
            lines.add("::1 " + d);
        }
        lines.add(END_PREFIX + " " + blockId);
        return lines;
    }

    private List<String> stripAllManagedBlocks(List<String> lines) {
        List<String> out = new ArrayList<>();
        boolean skip = false;
        for (String line : lines) {
            if (line.startsWith(START_PREFIX)) {
                skip = true;
                continue;
            }
            if (skip && line.startsWith(END_PREFIX)) {
                skip = false;
                continue;
            }
            if (!skip) {
                out.add(line);
            }
        }
        return out;
    }

    private void removeBlockById(Path hostsFile, String blockId) throws IOException {
        List<String> lines = Files.readAllLines(hostsFile);
        List<String> out = new ArrayList<>();
        boolean skip = false;
        for (String line : lines) {
            if (line.startsWith(START_PREFIX + " " + blockId + " ")) {
                skip = true;
                continue;
            }
            if (skip && line.equals(END_PREFIX + " " + blockId)) {
                skip = false;
                continue;
            }
            if (!skip) {
                out.add(line);
            }
        }
        Files.write(hostsFile, out);
    }

    private List<String> expandDomains(List<String> domains) {
        Set<String> expanded = new LinkedHashSet<>();
        for (String raw : domains) {
            String d = raw.trim().toLowerCase(Locale.ROOT);
            if (d.isBlank()) {
                continue;
            }
            if (d.startsWith("http://")) {
                d = d.substring("http://".length());
            } else if (d.startsWith("https://")) {
                d = d.substring("https://".length());
            }
            int slash = d.indexOf('/');
            if (slash >= 0) {
                d = d.substring(0, slash);
            }
            if (d.isBlank()) {
                continue;
            }
            expanded.addAll(expandOneDomain(d));
        }
        return new ArrayList<>(expanded);
    }

    private List<String> expandOneDomain(String domain) {
        Set<String> out = new LinkedHashSet<>();
        out.add(domain);
        if (!domain.startsWith("www.")) {
            out.add("www." + domain);
        }

        List<String> knownGroup = DOMAIN_GROUPS.get(domain);
        if (knownGroup != null) {
            out.addAll(knownGroup);
        }
        return new ArrayList<>(out);
    }

    private static Map<String, List<String>> buildDomainGroups() {
        Map<String, List<String>> m = new HashMap<>();
        m.put("youtube.com", Arrays.asList(
            "m.youtube.com",
            "music.youtube.com",
            "studio.youtube.com",
            "youtu.be",
            "www.youtu.be",
            "youtube-nocookie.com",
            "www.youtube-nocookie.com",
            "ytimg.com",
            "www.ytimg.com",
            "i.ytimg.com",
            "s.ytimg.com",
            "googlevideo.com",
            "www.googlevideo.com",
            "youtubei.googleapis.com"
        ));
        m.put("facebook.com", Arrays.asList(
            "m.facebook.com",
            "mbasic.facebook.com",
            "fbcdn.net",
            "www.fbcdn.net"
        ));
        m.put("instagram.com", Arrays.asList(
            "www.instagram.com",
            "m.instagram.com",
            "cdninstagram.com",
            "www.cdninstagram.com"
        ));
        return m;
    }

    private void flushDnsCacheBestEffort() {
        runQuietly("dscacheutil", "-flushcache");
        runQuietly("killall", "-HUP", "mDNSResponder");
    }

    private void runQuietly(String... cmd) {
        try {
            Process p = new ProcessBuilder(cmd).start();
            p.waitFor(3, TimeUnit.SECONDS);
        } catch (Exception ignored) {
            // Non-fatal. Live block still works in most cases without cache flush.
        }
    }
}

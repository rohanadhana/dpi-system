package com.packetanalyzer.dpi.app;

import com.packetanalyzer.dpi.engine.DpiProcessor;
import com.packetanalyzer.dpi.engine.LiveBlockService;
import com.packetanalyzer.dpi.engine.ProcessingOptions;
import com.packetanalyzer.dpi.engine.ProcessingReport;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.AccessDeniedException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Component
public class DpiCliRunner implements CommandLineRunner {
    private final DpiProcessor processor;
    private final LiveBlockService liveBlockService;

    public DpiCliRunner(DpiProcessor processor, LiveBlockService liveBlockService) {
        this.processor = processor;
        this.liveBlockService = liveBlockService;
    }

    @Override
    public void run(String... args) throws Exception {
        if (args.length == 0 || hasArg(args, "--help") || hasArg(args, "-h")) {
            printUsage();
            return;
        }

        List<String> positional = new ArrayList<>();
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        List<String> liveBlockDomains = new ArrayList<>();
        Path rulesFile = null;
        Duration liveDuration = Duration.ofMinutes(5);

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--block-ip".equals(arg) && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if ("--block-app".equals(arg) && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if ("--block-domain".equals(arg) && i + 1 < args.length) {
                String rawDomains = args[++i];
                for (String domain : rawDomains.split(",")) {
                    String trimmed = domain.trim();
                    if (!trimmed.isEmpty()) {
                        blockDomains.add(trimmed);
                    }
                }
            } else if ("--live-block-domain".equals(arg) && i + 1 < args.length) {
                String rawDomains = args[++i];
                for (String domain : rawDomains.split(",")) {
                    String trimmed = domain.trim();
                    if (!trimmed.isEmpty()) {
                        liveBlockDomains.add(trimmed);
                    }
                }
            } else if ("--duration".equals(arg) && i + 1 < args.length) {
                liveDuration = parseDuration(args[++i]);
            } else if ("--rules".equals(arg) && i + 1 < args.length) {
                rulesFile = Path.of(args[++i]);
            } else if (arg.startsWith("--")) {
                // Ignore unknown flags to keep CLI lenient like C++ sample.
            } else {
                positional.add(arg);
            }
        }

        if (!liveBlockDomains.isEmpty()) {
            System.out.println("[LIVE BLOCK] Starting timed domain blocking...");
            try {
                liveBlockService.blockDomainsForDuration(liveBlockDomains, liveDuration);
            } catch (AccessDeniedException e) {
                System.err.println("[LIVE BLOCK] Permission denied. Run with sudo to modify /etc/hosts.");
                throw e;
            }
            return;
        }

        if (positional.size() < 2) {
            printUsage();
            return;
        }

        Path input = Path.of(positional.get(0));
        Path output = Path.of(positional.get(1));

        System.out.println("\n[DPI] Processing packets...");
        ProcessingReport report = processor.process(new ProcessingOptions(
            input,
            output,
            blockIps,
            blockApps,
            blockDomains,
            rulesFile
        ));

        System.out.println(report.toPrettyText());
        System.out.println("Output written to: " + output.toAbsolutePath());
    }

    private boolean hasArg(String[] args, String value) {
        for (String arg : args) {
            if (value.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private void printUsage() {
        System.out.println("""
            DPI Engine - Deep Packet Inspection System (Java + Spring Boot)
            ===============================================================

            Usage:
              java -jar target/dpi-engine-1.0.0.jar <input.pcap> <output.pcap> [options]
              sudo java -jar target/dpi-engine-1.0.0.jar --live-block-domain <domain[,domain2]> --duration 5m

            Options:
              --block-ip <ip>        Block traffic from source IP
              --block-app <app>      Block application (YouTube, Facebook, etc.)
              --block-domain <dom>   Block domain (supports wildcard like *.facebook.com)
              --rules <file>         Load rule file with [BLOCKED_*] sections
              --live-block-domain    Live block website(s) via hosts file
              --duration <time>      Duration for live block: 300s, 5m, 1h
              --help                 Show this help

            Example:
              java -jar target/dpi-engine-1.0.0.jar test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
              sudo java -jar target/dpi-engine-1.0.0.jar --live-block-domain youtube.com --duration 5m
            """);
    }

    private Duration parseDuration(String raw) {
        String value = raw.trim().toLowerCase();
        if (value.endsWith("ms")) {
            return Duration.ofMillis(Long.parseLong(value.substring(0, value.length() - 2)));
        }
        if (value.endsWith("s")) {
            return Duration.ofSeconds(Long.parseLong(value.substring(0, value.length() - 1)));
        }
        if (value.endsWith("m")) {
            return Duration.ofMinutes(Long.parseLong(value.substring(0, value.length() - 1)));
        }
        if (value.endsWith("h")) {
            return Duration.ofHours(Long.parseLong(value.substring(0, value.length() - 1)));
        }
        return Duration.ofSeconds(Long.parseLong(value));
    }
}

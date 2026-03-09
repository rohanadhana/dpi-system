package com.packetanalyzer.dpi.engine;

import com.packetanalyzer.dpi.model.AppType;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public record ProcessingReport(
    long totalPackets,
    long forwardedPackets,
    long droppedPackets,
    int activeFlows,
    Map<AppType, Long> appBreakdown,
    Map<String, AppType> detectedDomains
) {
    public String toPrettyText() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");
        sb.append("╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                      PROCESSING REPORT                       ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Packets:      %10d                             ║%n", totalPackets));
        sb.append(String.format("║ Forwarded:          %10d                             ║%n", forwardedPackets));
        sb.append(String.format("║ Dropped:            %10d                             ║%n", droppedPackets));
        sb.append(String.format("║ Active Flows:       %10d                             ║%n", activeFlows));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION BREAKDOWN                     ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appBreakdown.entrySet());
        sorted.sort(Comparator.comparingLong((Map.Entry<AppType, Long> e) -> e.getValue()).reversed());
        for (Map.Entry<AppType, Long> e : sorted) {
            double pct = totalPackets == 0 ? 0 : (100.0 * e.getValue() / totalPackets);
            int barLen = (int) (pct / 5.0);
            String bar = "#".repeat(Math.max(0, barLen));
            sb.append(String.format("║ %-15s%8d %5.1f%% %-20s  ║%n", e.getKey().displayName(), e.getValue(), pct, bar));
        }
        sb.append("╚══════════════════════════════════════════════════════════════╝\n");

        sb.append("\n[Detected Applications/Domains]\n");
        for (Map.Entry<String, AppType> e : detectedDomains.entrySet()) {
            sb.append("  - ").append(e.getKey()).append(" -> ").append(e.getValue().displayName()).append("\n");
        }

        return sb.toString();
    }
}

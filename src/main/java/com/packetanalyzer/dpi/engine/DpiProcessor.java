package com.packetanalyzer.dpi.engine;

import com.packetanalyzer.dpi.model.AppType;
import com.packetanalyzer.dpi.model.FiveTuple;
import com.packetanalyzer.dpi.model.Flow;
import com.packetanalyzer.dpi.parser.PacketParser;
import com.packetanalyzer.dpi.parser.ParsedPacket;
import com.packetanalyzer.dpi.pcap.PcapPacket;
import com.packetanalyzer.dpi.pcap.PcapReader;
import com.packetanalyzer.dpi.pcap.PcapWriter;
import com.packetanalyzer.dpi.rules.RuleManager;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class DpiProcessor {
    public ProcessingReport process(ProcessingOptions options) throws IOException {
        RuleManager rules = new RuleManager();
        if (options.rulesFile() != null) {
            rules.loadFromFile(options.rulesFile());
        }
        options.blockedIps().forEach(rules::blockIp);
        options.blockedApps().forEach(rules::blockApp);
        options.blockedDomains().forEach(rules::blockDomain);

        Map<FiveTuple, Flow> flows = new HashMap<>();
        Map<AppType, Long> appStats = new EnumMap<>(AppType.class);

        long totalPackets = 0;
        long forwarded = 0;
        long dropped = 0;

        try (PcapReader reader = new PcapReader(options.inputFile());
             PcapWriter writer = new PcapWriter(options.outputFile(), reader.globalHeader())) {

            Optional<PcapPacket> next;
            while ((next = reader.readNextPacket()).isPresent()) {
                PcapPacket packet = next.get();
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(packet);
                if (!parsed.valid() || !parsed.hasIpv4() || (!parsed.hasTcp() && !parsed.hasUdp())) {
                    continue;
                }

                FiveTuple tuple = parsed.tuple();
                FiveTuple reverse = new FiveTuple(
                    tuple.dstIp(),
                    tuple.srcIp(),
                    tuple.dstPort(),
                    tuple.srcPort(),
                    tuple.protocol()
                );

                Flow flow = flows.get(tuple);
                if (flow == null) {
                    flow = flows.get(reverse);
                }
                if (flow == null) {
                    flow = new Flow(tuple);
                    flows.put(tuple, flow);
                }
                flow.increment(packet.data().length);

                if ((flow.appType() == AppType.UNKNOWN || flow.appType() == AppType.HTTPS)
                    && flow.sniOrHost().isEmpty() && parsed.hasTcp() && parsed.dstPort() == 443 && parsed.payloadLength() > 0) {
                    byte[] payload = slicePayload(packet.data(), parsed.payloadOffset(), parsed.payloadLength());
                    Optional<String> maybeSni = DomainExtractors.extractTlsSni(payload);
                    if (maybeSni.isPresent()) {
                        String sni = maybeSni.get();
                        flow.setSniOrHost(sni);
                        flow.setAppType(AppClassifier.classifyByDomain(sni));
                    }
                }

                if ((flow.appType() == AppType.UNKNOWN || flow.appType() == AppType.HTTP)
                    && flow.sniOrHost().isEmpty() && parsed.hasTcp() && parsed.dstPort() == 80 && parsed.payloadLength() > 0) {
                    byte[] payload = slicePayload(packet.data(), parsed.payloadOffset(), parsed.payloadLength());
                    Optional<String> maybeHost = DomainExtractors.extractHttpHost(payload);
                    if (maybeHost.isPresent()) {
                        String host = maybeHost.get();
                        flow.setSniOrHost(host);
                        flow.setAppType(AppClassifier.classifyByDomain(host));
                    }
                }

                if (flow.appType() == AppType.UNKNOWN && (parsed.srcPort() == 53 || parsed.dstPort() == 53)) {
                    flow.setAppType(AppType.DNS);
                }

                if (flow.appType() == AppType.UNKNOWN) {
                    if (parsed.dstPort() == 443) {
                        flow.setAppType(AppType.HTTPS);
                    } else if (parsed.dstPort() == 80) {
                        flow.setAppType(AppType.HTTP);
                    }
                }

                if (!flow.blocked()) {
                    RuleManager.BlockResult result = rules.shouldBlock(parsed.srcIp(), parsed.dstPort(), flow.appType(), flow.sniOrHost());
                    if (result.blocked()) {
                        flow.setBlocked(true);
                        System.out.printf("[BLOCKED] %s -> %s (%s)%n",
                            parsed.srcIpText(), parsed.dstIpText(), flow.appType().displayName());
                    }
                }

                appStats.merge(flow.appType(), 1L, Long::sum);

                if (flow.blocked()) {
                    dropped++;
                } else {
                    forwarded++;
                    writer.writePacket(packet);
                }
            }
        }

        Map<String, AppType> detectedDomains = new HashMap<>();
        for (Flow f : flows.values()) {
            if (!f.sniOrHost().isBlank()) {
                detectedDomains.put(f.sniOrHost(), f.appType());
            }
        }

        return new ProcessingReport(totalPackets, forwarded, dropped, flows.size(), appStats, detectedDomains);
    }

    private byte[] slicePayload(byte[] packet, int payloadOffset, int payloadLength) {
        if (payloadOffset < 0 || payloadOffset >= packet.length || payloadLength <= 0) {
            return new byte[0];
        }
        int end = Math.min(packet.length, payloadOffset + payloadLength);
        return Arrays.copyOfRange(packet, payloadOffset, end);
    }
}

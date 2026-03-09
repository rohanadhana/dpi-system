package com.packetanalyzer.dpi.engine;

import java.nio.file.Path;
import java.util.List;

public record ProcessingOptions(
    Path inputFile,
    Path outputFile,
    List<String> blockedIps,
    List<String> blockedApps,
    List<String> blockedDomains,
    Path rulesFile
) {
}

# DPI Engine (Java + Spring Boot)

This project is a Java/Spring Boot port of the C++ DPI packet analyzer.

## Features

- PCAP input and PCAP output processing
- Ethernet + IPv4 + TCP/UDP parsing
- Five-tuple flow tracking
- TLS ClientHello SNI extraction (HTTPS)
- HTTP Host header extraction (HTTP)
- App classification (YouTube, Facebook, TikTok, etc.)
- Rule-based blocking:
  - Source IP
  - Application
  - Domain (exact, wildcard, or substring)
  - Rule file sections `[BLOCKED_IPS]`, `[BLOCKED_APPS]`, `[BLOCKED_DOMAINS]`, `[BLOCKED_PORTS]`
- Processing report with app breakdown and detected domains

## Build

```bash
cd /Users/rohanadhana/Documents/PacketAnalyzerProject/Packet_analyzer_springboot
mvn clean package
```

## Run

```bash
java -jar target/dpi-engine-1.0.0.jar \
  /Users/rohanadhana/Documents/PacketAnalyzerProject/Packet_analyzer-main/test_dpi.pcap \
  /Users/rohanadhana/Documents/PacketAnalyzerProject/Packet_analyzer_springboot/filtered_output.pcap \
  --block-app YouTube --block-domain *.tiktok.com
```

## Live Blocking (Real-Time, Timed)

This mode modifies your system hosts file temporarily, blocks domain resolution immediately, waits for the duration, then automatically removes the block.

```bash
sudo java -jar target/dpi-engine-1.0.0.jar \
  --live-block-domain youtube.com \
  --duration 5m
```

Multiple websites:

```bash
sudo java -jar target/dpi-engine-1.0.0.jar \
  --live-block-domain youtube.com,facebook.com,instagram.com \
  --duration 5m
```

Duration formats:
- `300s`
- `5m`
- `1h`

Notes:
- This blocks exact domains and their `www.` variant.
- Browser DNS cache may delay effect for already-open sessions; close/reopen browser tab if needed.
- Requires admin privileges (`sudo`) because `/etc/hosts` is protected.

## Rules File Example

```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com
tiktok

[BLOCKED_PORTS]
25
```

## Notes

- This is designed as an offline DPI pipeline on PCAP files, matching the C++ behavior.
- It is packaged with Spring Boot for dependency management, startup, and extensibility.

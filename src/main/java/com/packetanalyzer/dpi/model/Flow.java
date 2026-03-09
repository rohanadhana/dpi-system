package com.packetanalyzer.dpi.model;

public class Flow {
    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sniOrHost = "";
    private long packets;
    private long bytes;
    private boolean blocked;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple tuple() { return tuple; }
    public AppType appType() { return appType; }
    public String sniOrHost() { return sniOrHost; }
    public long packets() { return packets; }
    public long bytes() { return bytes; }
    public boolean blocked() { return blocked; }

    public void setAppType(AppType appType) { this.appType = appType; }
    public void setSniOrHost(String sniOrHost) { this.sniOrHost = sniOrHost; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }

    public void increment(long packetBytes) {
        this.packets++;
        this.bytes += packetBytes;
    }
}

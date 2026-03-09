package com.packetanalyzer.dpi.engine;

import com.packetanalyzer.dpi.model.AppType;

import java.util.Locale;

public final class AppClassifier {
    private AppClassifier() {
    }

    public static AppType classifyByDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return AppType.UNKNOWN;
        }

        String s = domain.toLowerCase(Locale.ROOT);

        if (containsAny(s, "youtube", "ytimg", "youtu.be", "yt3.ggpht")) return AppType.YOUTUBE;
        if (containsAny(s, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return AppType.GOOGLE;
        if (containsAny(s, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) return AppType.FACEBOOK;
        if (containsAny(s, "instagram", "cdninstagram")) return AppType.INSTAGRAM;
        if (containsAny(s, "whatsapp", "wa.me")) return AppType.WHATSAPP;
        if (containsAny(s, "twitter", "twimg", "x.com", "t.co")) return AppType.TWITTER;
        if (containsAny(s, "netflix", "nflxvideo", "nflximg")) return AppType.NETFLIX;
        if (containsAny(s, "amazon", "amazonaws", "cloudfront", "aws")) return AppType.AMAZON;
        if (containsAny(s, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) return AppType.MICROSOFT;
        if (containsAny(s, "apple", "icloud", "mzstatic", "itunes")) return AppType.APPLE;
        if (containsAny(s, "telegram", "t.me")) return AppType.TELEGRAM;
        if (containsAny(s, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) return AppType.TIKTOK;
        if (containsAny(s, "spotify", "scdn.co")) return AppType.SPOTIFY;
        if (containsAny(s, "zoom")) return AppType.ZOOM;
        if (containsAny(s, "discord", "discordapp")) return AppType.DISCORD;
        if (containsAny(s, "github", "githubusercontent")) return AppType.GITHUB;
        if (containsAny(s, "cloudflare", "cf-")) return AppType.CLOUDFLARE;

        return AppType.HTTPS;
    }

    private static boolean containsAny(String source, String... terms) {
        for (String t : terms) {
            if (source.contains(t)) {
                return true;
            }
        }
        return false;
    }
}

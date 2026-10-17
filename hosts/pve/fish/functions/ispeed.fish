function __ispeed_help
    echo "Usage: ispeed [-d|--down MB] [-u|--up MB] [-n|--pings N]"
    echo ""
    echo "Measures internet speed against Cloudflare's speed test (speed.cloudflare.com)"
    echo "with curl: latency and jitter, then one download and one upload stream."
    echo ""
    echo "  -d/--down MB    Download size in MB (default 90, at most 99)"
    echo "  -u/--up MB      Upload size in MB (default 25)"
    echo "  -n/--pings N    Latency samples (default 10)"
    echo "  -h/--help       Show this help"
    echo ""
    echo "Bars are scaled to the default route's link speed, which caps the result."
    echo "A run moves about down + up MB of real traffic."
end

# Runs curl in the background with a spinner on a terminal; prints curl's -w line.
function __ispeed_curl -a label
    set -l out (mktemp)
    curl -sS -o /dev/null $argv[2..-1] >$out 2>/dev/null &
    set -l pid $last_pid
    set -l frames ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏
    set -l i 1
    while kill -0 $pid 2>/dev/null
        if test -t 2
            set_color $gruvbox_blue >&2
            printf '\r  %s %s' $frames[$i] $label >&2
            set_color normal >&2
        end
        set i (math $i % 10 + 1)
        sleep 0.1
    end
    test -t 2; and printf '\r\e[2K' >&2
    command cat $out
    command rm -f $out
end

# Mbit/s with a sensible precision.
function __ispeed_rate -a mbps
    if test $mbps -ge 1000
        printf '%.2f Gbit/s' (math "$mbps / 1000")
    else if test $mbps -ge 100
        printf '%.0f Mbit/s' $mbps
    else
        printf '%.1f Mbit/s' $mbps
    end
end

# One result row: label, bar scaled to the link (when known), rate, detail.
function __ispeed_row -a label mbps link detail
    set_color --bold
    printf '  %-9s' $label
    set_color normal
    if test -n "$link"
        set -l width 28
        set -l filled (math "min($width, round($mbps / $link * $width))")
        set -l ratio (math "$mbps / $link")
        set -l color $gruvbox_orange
        test $ratio -ge 0.3; and set color $gruvbox_yellow
        test $ratio -ge 0.7; and set color $gruvbox_green
        set_color $color
        printf '%s' (string repeat -n $filled -- █) ''
        set_color brblack
        printf '%s' (string repeat -n (math $width - $filled) -- ░) ''
        set_color normal
        printf '  '
    end
    set_color --bold $gruvbox_aqua
    printf '%-12s' (__ispeed_rate $mbps)
    set_color brblack
    printf '  %s\n' $detail
    set_color normal
end

function ispeed -d "Internet speed test (Cloudflare): latency, jitter, download, upload"
    argparse h/help 'd/down=!_validate_int --min 1 --max 99' 'u/up=!_validate_int --min 1' 'n/pings=!_validate_int --min 2' -- $argv
    or return 1
    if set -q _flag_help
        __ispeed_help
        return 0
    end
    set -l down 90
    set -l up 25
    set -l pings 10
    set -q _flag_down; and set down $_flag_down
    set -q _flag_up; and set up $_flag_up
    set -q _flag_pings; and set pings $_flag_pings
    set -l base https://speed.cloudflare.com

    # Link speed of the default route's device (for a bridge: its first physical port with a speed).
    set -l link
    set -l link_desc
    set -l dev
    command -q ip; and set dev (ip route show default 2>/dev/null | string match -r 'dev (\S+)' | tail -n 1)
    if test -n "$dev"
        set -l ports $dev
        test -d /sys/class/net/$dev/brif; and set ports (path basename /sys/class/net/$dev/brif/*)
        for p in $ports
            # Skip virtual bridge ports (guest taps, firewall veths): only NICs have a device.
            test "$p" != "$dev"; and not test -e /sys/class/net/$p/device; and continue
            set -l s (cat /sys/class/net/$p/speed 2>/dev/null)
            if string match -qr '^[1-9][0-9]*$' -- "$s"
                set link $s
                set link_desc $p
                test "$p" != "$dev"; and set link_desc "$p via $dev"
                break
            end
        end
    end

    # Edge location and public address from the response headers.
    set -l headers (curl -sS --max-time 5 -D - -o /dev/null "$base/__down?bytes=0" 2>/dev/null)
    if test -z "$headers"
        set_color $gruvbox_red
        echo "✗ cannot reach $base — offline or blocked" >&2
        set_color normal
        return 1
    end
    set -l colo (string match -ri '^cf-ray: \S+-([A-Z]{3})' -- $headers)[2]
    set -l ip (string match -ri '^cf-meta-ip: (\S+)' -- $headers)[2]
    test -n "$colo"; or set colo ?
    test -n "$ip"; or set ip ?

    set_color --bold $gruvbox_aqua
    printf '◆ Internet speed'
    set_color normal
    set_color brblack
    printf '  Cloudflare %s · %s · %s\n' $colo $ip (hostname -s)
    set_color normal
    if test -n "$link"
        set_color --bold
        printf '  %-9s' Link
        set_color normal
        printf '%s' (__ispeed_rate $link)
        set_color brblack
        printf '  %s\n' $link_desc
        set_color normal
    end

    # Latency: TCP handshake time of fresh connections; jitter = mean change between samples.
    set -l rtts
    for i in (seq $pings)
        set -l w (__ispeed_curl "latency $i/$pings" --max-time 5 -w '%{exitcode} %{time_namelookup} %{time_connect}' "$base/__down?bytes=0")
        set -l f (string split ' ' -- $w)
        test "$f[1]" = 0; or continue
        set -a rtts (math "($f[3] - $f[2]) * 1000")
    end
    if test (count $rtts) -lt 2
        set_color $gruvbox_red
        echo "✗ latency probes failed" >&2
        set_color normal
        return 1
    end
    set -l sorted (printf '%s\n' $rtts | sort -n)
    set -l median $sorted[(math "ceil($(count $sorted) / 2)")]
    set -l jitter 0
    for i in (seq 2 (count $rtts))
        set -l prev (math $i - 1)
        set jitter (math "$jitter + abs($rtts[$i] - $rtts[$prev])")
    end
    set jitter (math "$jitter / ($(count $rtts) - 1)")
    set -l lcolor $gruvbox_green
    test $median -ge 30; and set lcolor $gruvbox_yellow
    test $median -ge 80; and set lcolor $gruvbox_orange
    set_color --bold
    printf '  %-9s' Latency
    set_color normal
    set_color --bold $lcolor
    printf '%.1f ms' $median
    set_color normal
    set_color brblack
    printf '  jitter %.1f ms · min %.1f · max %.1f · %d samples\n' $jitter $sorted[1] $sorted[-1] (count $rtts)
    set_color normal

    # Download.
    set -l bytes (math "$down * 1000000")
    set -l w (__ispeed_curl "downloading $down MB" --max-time 120 -w '%{exitcode} %{http_code} %{speed_download} %{time_total}' "$base/__down?bytes=$bytes")
    set -l f (string split ' ' -- $w)
    if test "$f[1]" = 0 -a "$f[2]" = 200
        __ispeed_row Download (math "$f[3] * 8 / 1000000") "$link" (printf '%d MB in %.1f s' $down $f[4])
    else
        set_color $gruvbox_red
        printf '  %-9s✗ failed (curl %s, HTTP %s)\n' Download $f[1] $f[2]
        set_color normal
    end

    # Upload (zeros from a temp file; HTTP bodies are not compressed).
    set -l tmp (mktemp)
    head -c (math "$up * 1000000") /dev/zero >$tmp
    set w (__ispeed_curl "uploading $up MB" --max-time 120 -X POST -H 'Content-Type: application/octet-stream' --data-binary @$tmp -w '%{exitcode} %{http_code} %{speed_upload} %{time_total}' "$base/__up")
    command rm -f $tmp
    set f (string split ' ' -- $w)
    if test "$f[1]" = 0 -a "$f[2]" = 200
        __ispeed_row Upload (math "$f[3] * 8 / 1000000") "$link" (printf '%d MB in %.1f s' $up $f[4])
    else
        set_color $gruvbox_red
        printf '  %-9s✗ failed (curl %s, HTTP %s)\n' Upload $f[1] $f[2]
        set_color normal
    end
end

function __killport_help
    echo "Usage: killport [-f|--force] <port>"
    echo ""
    echo "Kills the process(es) holding a TCP/UDP port."
    echo ""
    echo "  default   SIGTERM (graceful)"
    echo "  -f/--force  SIGKILL (forced)"
    echo "  -h/--help   Show this help"
    echo ""
    echo "Shows the holders first and asks before killing."
end

function killport -d "Kill the process(es) holding a TCP/UDP port, asking first"
    argparse h/help f/force -- $argv
    or return 1

    if set -q _flag_help
        __killport_help
        return 0
    end
    if test (count $argv) -ne 1
        __killport_help >&2
        return 1
    end

    set -l port $argv[1]
    if not string match -qr '^[0-9]+$' -- $port; or test $port -eq 0; or test $port -gt 65535
        set_color $gruvbox_red
        echo "✗ invalid port: $port" >&2
        set_color normal
        return 1
    end

    set -l rows (sudo ss -tulnp "sport = :$port")
    if test $status -ne 0
        set_color $gruvbox_red
        echo "✗ could not query sockets (sudo denied?)" >&2
        set_color normal
        return 1
    end

    set -l pids
    set -l names
    for row in $rows[2..-1]
        for pidmatch in (string match -ra 'pid=\d+' -- $row)
            set -l pid (string replace -r '^pid=' '' -- $pidmatch)
            contains -- $pid $pids; or set -a pids $pid
        end
        for nm in (string match -ra '"[^"]+"' -- $row)
            set nm (string trim --chars='"' -- $nm)
            contains -- $nm $names; or set -a names $nm
        end
    end

    if test (count $pids) -eq 0
        set_color $gruvbox_green
        echo "✓ nothing holds port $port"
        set_color normal
        return 0
    end

    set_color --bold $gruvbox_aqua
    printf "◆ port %s held by %s\n" $port (string join ', ' $names)
    set_color $gruvbox_blue
    printf "  pid(s): %s\n" (string join ', ' $pids)
    set_color normal

    set -l sig TERM
    set -l label "SIGTERM (graceful)"
    if set -q _flag_force
        set sig KILL
        set label "SIGKILL (forced)"
    end

    read -P "Send $label to "(count $pids)" process(es)? [y/N] " -l answer
    if not string match -qr '^[Yy]$' -- "$answer"
        echo "Cancelled."
        return 1
    end

    if /bin/kill -$sig $pids
        set_color $gruvbox_green
        echo "✓ sent $label to: "(string join ', ' $pids)
        set_color normal
        return 0
    end
    set_color $gruvbox_red
    echo "✗ at least one signal could not be delivered (already exited?)" >&2
    set_color normal
    return 1
end

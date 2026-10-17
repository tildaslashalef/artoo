function __ports_help
    echo "Usage: ports [-c|--connections] [filter]"
    echo ""
    echo "Socket overview from `ss` (uses sudo to attribute PIDs)."
    echo ""
    echo "Options:"
    echo "  -c, --connections  Established connections instead of listeners"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Examples:"
    echo "  ports             # all listening sockets"
    echo "  ports 8080        # just rows matching 8080"
    echo "  ports -c          # established connections"
    echo "  ports -c ssh      # established connections involving ssh"
end

function ports -d "Listening sockets or established connections as a gruvbox table"
    argparse h/help c/connections -- $argv
    or return 1

    if set -q _flag_help
        __ports_help
        return 0
    end

    set -l filter $argv[1]
    set -l rows
    set -l estab 0
    if set -q _flag_connections
        set estab 1
        set rows (sudo ss -tnp state established)
    else
        set rows (sudo ss -tulnp)
    end
    if test $status -ne 0
        set_color $gruvbox_red
        echo "✗ could not query sockets (sudo denied?)" >&2
        set_color normal
        return 1
    end

    set_color --bold $gruvbox_aqua
    if test $estab -eq 1
        echo "◆ established connections"
        set_color $gruvbox_yellow
        printf "%-24s %-24s %-12s %s\n" LOCAL PEER PROGRAM PID
    else
        echo "◆ listening sockets"
        set_color $gruvbox_yellow
        printf "%-8s %-24s %-12s %s\n" STATE LOCAL PROGRAM PID
    end
    set_color normal

    for row in $rows[2..-1]
        set -l f (string match -ra '\S+' -- $row)
        if test $estab -eq 1
            test (count $f) -ge 5; or continue
        else
            test (count $f) -ge 4; or continue
        end
        if set -q filter[1]
            string match -qi "*$filter*" -- $row; or continue
        end

        set -l prog -
        set -l pid -
        set -l names (string match -ra '"[^"]+"' -- $row)
        test (count $names) -gt 0; and set prog (string trim --chars='"' -- $names[1])
        set -l pids (string match -ra 'pid=\d+' -- $row)
        test (count $pids) -gt 0; and set pid (string replace -r '^pid=' '' -- $pids[1])

        if test $estab -eq 1
            set_color $gruvbox_purple
            printf "%-24s " $f[4]
            printf "%-24s " $f[5]
        else
            set_color $gruvbox_purple
            printf "%-8s %-24s " $f[1] $f[4]
        end
        set_color $gruvbox_green
        printf "%-12s " $prog
        set_color $gruvbox_blue
        printf "%s\n" $pid
        set_color normal
    end
end

function myip -d "Show LAN addresses and public IP"
    set_color $gruvbox_blue
    echo "📍 Local:"
    set_color normal
    for line in (ip -4 -brief address show scope global)
        set -l parts (string match -ra '\S+' -- $line)
        test (count $parts) -ge 3; or continue
        set_color $gruvbox_aqua
        printf "  %-12s" $parts[1]
        set_color normal
        printf " %s\n" (string join ', ' $parts[3..-1])
    end

    set -l public_ip (curl -s --max-time 3 https://api.ipify.org)
    set_color $gruvbox_blue
    echo "🌍 Public:"
    set_color normal
    if test -n "$public_ip"
        echo "  $public_ip"
    else
        set_color $gruvbox_yellow
        echo "  (could not reach ipify — offline or blocked)"
        set_color normal
    end
end

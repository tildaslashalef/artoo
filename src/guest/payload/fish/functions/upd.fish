function upd -d "apt: update index, show upgradable count, upgrade after confirmation"
    set_color $gruvbox_blue
    echo "◆ updating package index…"
    set_color normal
    sudo apt update
    or return 1

    set -l n (apt list --upgradable 2>/dev/null | string match -ra 'upgradable from' | count)
    if test $n -eq 0
        set_color $gruvbox_green
        echo "✓ system up to date"
        set_color normal
        return 0
    end
    set_color $gruvbox_yellow
    echo "◆ $n package(s) can be upgraded ('apt list --upgradable' to inspect)"
    set_color normal

    read -P "Upgrade now? [y/N] " -l answer
    if not string match -qr '^[Yy]$' -- "$answer"
        echo "Cancelled."
        return 0
    end
    sudo apt upgrade
    or return 1

    read -P "Autoremove no-longer-needed packages? [y/N] " -l answer
    if string match -qr '^[Yy]$' -- "$answer"
        sudo apt autoremove
    end
end

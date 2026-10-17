function __pveupd_help
    echo "Usage: pveupd [-y|--yes]"
    echo ""
    echo "Updates the Proxmox host the supported way (apt full-upgrade)."
    echo ""
    echo "  1. apt update, then the upgradable packages (Proxmox/kernel/ZFS first)"
    echo "  2. running guests (a new kernel only takes effect after a reboot)"
    echo "  3. apt full-upgrade — apt shows its summary and asks (-y skips it)"
    echo "  4. optional autoremove, then whether a reboot is needed"
    echo ""
    echo "  -y/--yes    Pass -y to apt (no apt prompt)"
    echo "  -h/--help   Show this help"
    echo ""
    echo "Never reboots by itself. Plain 'apt upgrade' is not used: on Proxmox it"
    echo "can hold packages back and leave the stack half-upgraded."
end

function pveupd -d "Proxmox host update: apt full-upgrade with a summary and reboot check"
    argparse h/help y/yes -- $argv
    or return 1
    if set -q _flag_help
        __pveupd_help
        return 0
    end
    if test (id -u) -ne 0
        set_color $gruvbox_red
        echo "✗ run as root" >&2
        set_color normal
        return 1
    end
    if not command -q pveversion
        set_color $gruvbox_red
        echo "✗ not a Proxmox VE host (use 'upd' on guests)" >&2
        set_color normal
        return 1
    end

    set_color --bold $gruvbox_aqua
    echo "◆ "(pveversion)
    set_color $gruvbox_blue
    echo "◆ updating package index…"
    set_color normal
    apt update
    or return 1

    set -l pending (apt list --upgradable 2>/dev/null | string match -r '^[^/]+/' | string replace -r '/$' '')
    set -l pve (string match -r '^(pve-|proxmox-|qemu-server|libpve|zfs|libzfs|lxc-pve|corosync|ceph)' -- $pending)
    if test (count $pending) -eq 0
        set_color $gruvbox_green
        echo "✓ no package upgrades"
        set_color normal
    else
        set_color $gruvbox_yellow
        printf "◆ %d package(s) upgradable, %d of them Proxmox/kernel/ZFS\n" (count $pending) (count $pve)
        set_color normal
        for p in $pve
            echo "    $p"
        end

        set -l running (qm list 2>/dev/null | string match -r '^\s*\d+\s+\S+\s+running' | string replace -r '^\s*(\d+)\s+(\S+).*' '$2 ($1)')
        if test (count $running) -gt 0
            set_color $gruvbox_blue
            echo "◆ running guests (keep running; Proxmox services restart briefly): "(string join ', ' $running)
            set_color normal
        end

        set -l yes
        set -q _flag_yes; and set yes -y
        apt full-upgrade $yes
        or return 1

        read -P "Autoremove no-longer-needed packages? [y/N] " -l answer
        if string match -qr '^[Yy]$' -- "$answer"
            apt autoremove
        end
        set_color --bold $gruvbox_aqua
        echo "◆ "(pveversion)
        set_color normal
    end

    # Reboot needed when the kernel that would boot is not the running one.
    set -l running_kernel (uname -r)
    set -l boot_kernel (proxmox-boot-tool kernel list 2>/dev/null | string match -r 'Pinned kernel:\s*\S+' | string replace -r '.*:\s*' '')
    if test -z "$boot_kernel"
        set boot_kernel (path basename /boot/vmlinuz-*-pve | string replace 'vmlinuz-' '' | sort -V | tail -n 1)
    end
    if test -n "$boot_kernel"; and test "$boot_kernel" != "$running_kernel"
        set_color $gruvbox_orange
        echo "▲ reboot needed: running $running_kernel, next boot $boot_kernel"
        echo "  guests with onboot=1 start again; shut the others down cleanly first ('qm list')"
        set_color normal
    else
        set_color $gruvbox_green
        echo "✓ running the newest kernel ($running_kernel)"
        set_color normal
    end
end

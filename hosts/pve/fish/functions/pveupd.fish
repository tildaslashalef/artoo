function __pveupd_help
    echo "Usage: pveupd [-c|--check] [-a|--all] [-y|--yes]"
    echo ""
    echo "Updates the Proxmox host the supported way (apt full-upgrade)."
    echo ""
    echo "  1. apt update, then a simulated full-upgrade: what would change"
    echo "     (Proxmox/kernel/ZFS packages by name, security updates, a new"
    echo "     kernel or QEMU, running guests)"
    echo "  2. refuses when the upgrade would remove a Proxmox core package"
    echo "  3. apt full-upgrade — apt shows its summary and asks (-y skips it)"
    echo "  4. optional autoremove, then whether a reboot is needed"
    echo ""
    echo "  -c/--check  Stop after step 1: install nothing"
    echo "  -a/--all    List every package, not only the Proxmox ones"
    echo "  -y/--yes    Pass -y to apt (no apt prompt)"
    echo "  -h/--help   Show this help"
    echo ""
    echo "Never reboots by itself. Plain 'apt upgrade' is not used: on Proxmox it"
    echo "can hold packages back and leave the stack half-upgraded."
end

# A label column, as artoo's plans: "  Label     text".
function __pveupd_label -a label
    set_color brblack
    printf '  %-9s ' $label
    set_color normal
end

function __pveupd_rows -a width
    # argv[2..]: "name|old|new|security" records.
    set -l first 1
    for r in $argv[2..-1]
        set -l f (string split '|' -- $r)
        if test $first -eq 1
            set first 0
        else
            printf '  %-9s ' ''
        end
        printf '%s  ' (string pad -r -w $width -- $f[1])
        set_color brblack
        if test -n "$f[2]"
            printf '%s' $f[2]
        else
            printf '(new)'
        end
        printf ' → '
        set_color normal
        set_color $gruvbox_aqua
        printf '%s' $f[3]
        set_color normal
        if test "$f[4]" = 1
            set_color $gruvbox_yellow
            printf ' (security)'
            set_color normal
        end
        printf '\n'
    end
end

function __pveupd_kernel_check
    # Reboot needed when the kernel that would boot is not the running one.
    set -l running_kernel (uname -r)
    set -l boot_kernel (proxmox-boot-tool kernel list 2>/dev/null | string match -r 'Pinned kernel:\s*\S+' | string replace -r '.*:\s*' '')
    if test -z "$boot_kernel"
        set boot_kernel (path basename /boot/vmlinuz-*-pve | string replace 'vmlinuz-' '' | sort -V | tail -n 1)
    end
    __pveupd_label Reboot
    if test -n "$boot_kernel"; and test "$boot_kernel" != "$running_kernel"
        set_color $gruvbox_orange
        echo "▲ needed: running $running_kernel, next boot $boot_kernel"
        set_color normal
        # Proxmox's pve-guests service shuts every guest down cleanly on a
        # host reboot and starts the onboot=1 ones again, in startup order.
        set -l back
        set -l stay
        for vm in (qm list 2>/dev/null | string match -r '^\s*\d+\s+\S+\s+running.*' | string replace -r '^\s*(\d+)\s+(\S+).*' '$1 $2')
            set -l f (string split ' ' -- $vm)
            if qm config $f[1] 2>/dev/null | string match -qr '^onboot:\s*1'
                set -a back $f[2]
            else
                set -a stay $f[2]
            end
        end
        printf '  %-9s %s\n' '' "'reboot' shuts every guest down cleanly and starts the onboot ones again"
        if test (count $stay) -gt 0
            printf '  %-9s ' ''
            set_color $gruvbox_orange
            echo "▲ running now, not started again (onboot off): "(string join ', ' $stay)
            set_color normal
        else if test (count $back) -gt 0
            printf '  %-9s ' ''
            set_color brblack
            echo "all "(count $back)" running guests start again"
            set_color normal
        end
    else
        set_color $gruvbox_green
        echo "✓ not needed: running the newest kernel ($running_kernel)"
        set_color normal
    end
end

function pveupd -d "Proxmox host update: apt full-upgrade with a summary, safety check and reboot check"
    argparse h/help c/check a/all y/yes -- $argv
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
    echo "◆ Proxmox update · "(hostname)
    set_color normal
    __pveupd_label Version
    echo (pveversion)

    __pveupd_label Index
    set_color $gruvbox_blue
    echo "updating package lists…"
    set_color normal
    if not apt-get -q -q update
        set_color $gruvbox_red
        echo "✗ apt update failed (see above); check Datacenter → "(hostname)" → Repositories" >&2
        set_color normal
        return 1
    end

    # What a full-upgrade would do, from apt's own simulation.
    set -l sim (env LC_ALL=C apt-get -s -q full-upgrade 2>&1)
    or begin
        set_color $gruvbox_red
        echo "✗ apt-get -s full-upgrade failed:" >&2
        set_color normal
        printf '    %s\n' $sim[-3..-1] >&2
        return 1
    end
    set -l pve_re '^(?:pve-|proxmox-|qemu-server|libpve|zfs|libzfs|lxc-pve|corosync|ceph|spl)'
    set -l proxmox
    set -l other
    set -l security
    set -l new_kernel
    set -l qemu
    set -l width 4
    set -l total 0
    set -l added 0
    for line in (string match -r '^Inst .*' -- $sim)
        set -l name (string match -rg '^Inst (\S+)' -- $line)
        set -l old (string match -rg '^Inst \S+ \[([^\]]+)\]' -- $line)
        set -l new (string match -rg '\((\S+) ' -- $line)
        set -l origin (string match -rg '\(\S+ (\S+)' -- $line)
        set -l sec 0
        string match -q '*-security*' -- $origin; and set sec 1
        set total (math $total + 1)
        test -z "$old"; and set added (math $added + 1)
        test $sec -eq 1; and set -a security $name
        set width (math "max($width, "(string length -- $name)")")
        set -l rec "$name|$old|$new|$sec"
        if string match -qr -- $pve_re $name
            set -a proxmox $rec
        else
            set -a other $rec
        end
        if test -z "$old"; and string match -qr '^proxmox-kernel-\d.*-pve(-signed)?$' -- $name
            set new_kernel (string replace -r '^proxmox-kernel-' '' -- $name | string replace -r -- '-signed$' '')
        end
        test "$name" = pve-qemu-kvm; and set qemu "$old → $new"
    end
    set -l removed (string match -rg '^Remv (\S+)' -- $sim)

    __pveupd_label Upgrade
    if test $total -eq 0 -a (count $removed) -eq 0
        set_color $gruvbox_green
        echo "✓ nothing to upgrade"
        set_color normal
        __pveupd_kernel_check
        return 0
    end
    printf '%d package(s), %d new, %d removed\n' $total $added (count $removed)

    # Never let an upgrade take Proxmox itself away (a broken or mixed repository).
    set -l kernel (uname -r)
    set -l core (string match -r '^(?:proxmox-ve|pve-manager|qemu-server|pve-qemu-kvm|pve-cluster|proxmox-kernel-'(string escape --style=regex -- $kernel)'(?:-signed)?)$' -- $removed)
    if test (count $core) -gt 0
        set_color $gruvbox_red
        echo "✗ the upgrade would remove "(string join ', ' $core)" — check Datacenter → "(hostname)" → Repositories; nothing was installed" >&2
        set_color normal
        return 1
    end

    if test (count $proxmox) -gt 0
        __pveupd_label Proxmox
        __pveupd_rows $width $proxmox
    end
    if set -q _flag_all; and test (count $other) -gt 0
        __pveupd_label Other
        __pveupd_rows $width $other
    else if test (count $other) -gt 0
        __pveupd_label Other
        set_color brblack
        echo (count $other)" package(s) ('pveupd -c -a' lists them)"
        set_color normal
    end
    if test (count $security) -gt 0
        __pveupd_label Security
        set_color $gruvbox_yellow
        echo (count $security)": "(string join ', ' $security)
        set_color normal
    end
    if test (count $removed) -gt 0
        __pveupd_label Remove
        set_color $gruvbox_orange
        echo (string join ', ' $removed)
        set_color normal
    end
    if test -n "$new_kernel"
        __pveupd_label Kernel
        set_color $gruvbox_orange
        echo "▲ new kernel $new_kernel — used after a host reboot"
        set_color normal
    end
    set -l running (qm list 2>/dev/null | string match -r '^\s*\d+\s+\S+\s+running.*' | string replace -r '^\s*(\d+)\s+(\S+).*' '$2')
    if test -n "$qemu"
        __pveupd_label QEMU
        set_color $gruvbox_orange
        echo "▲ pve-qemu-kvm $qemu — running VMs keep the old QEMU until stopped and started (a host reboot does it)"
        set_color normal
    end
    __pveupd_label Guests
    if test (count $running) -gt 0
        echo (count $running)" running, they keep running; Proxmox services restart briefly"
        printf '  %-9s ' ''
        set_color brblack
        echo (string join ', ' $running)
        set_color normal
    else
        echo "none running"
    end

    if set -q _flag_check
        echo ""
        set_color $gruvbox_green
        echo "✓ check only: nothing was installed — 'pveupd' installs it"
        set_color normal
        __pveupd_kernel_check
        return 0
    end

    echo ""
    set -l yes
    set -q _flag_yes; and set yes -y
    apt full-upgrade $yes
    or return 1

    set -l autoremove (env LC_ALL=C apt-get -s -q autoremove 2>/dev/null | string match -rg '^Remv (\S+)')
    if test (count $autoremove) -gt 0
        echo ""
        __pveupd_label Cleanup
        echo (string join ', ' $autoremove)
        read -P "  Remove these no-longer-needed packages? [y/N] " -l answer
        if string match -qr '^[Yy]$' -- "$answer"
            apt-get -q -y autoremove
        end
    end

    echo ""
    set_color --bold $gruvbox_aqua
    echo "◆ done · "(pveversion)
    set_color normal
    __pveupd_kernel_check
end

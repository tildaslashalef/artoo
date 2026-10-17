function __journal_help
    echo "Usage: journal [-b|--boot] [unit]"
    echo ""
    echo "Follows systemd logs: 'journal nginx', or everything without a unit."
    echo ""
    echo "  -b, --boot   Restrict to the current boot"
    echo "  -h, --help   Show this help"
end

function journal -d "Follow a systemd unit log (all units when none given)"
    argparse h/help b/boot -- $argv
    or return 1

    if set -q _flag_help
        __journal_help
        return 0
    end
    if test (count $argv) -gt 1
        __journal_help >&2
        return 1
    end

    set -l boot ""
    if set -q _flag_boot
        set boot -b
    end
    if test (count $argv) -eq 1
        sudo journalctl $boot -fu "$argv[1]"
    else
        sudo journalctl $boot -f
    end
end

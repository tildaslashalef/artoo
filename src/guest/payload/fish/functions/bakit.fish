function __bakit_help
    echo "Usage: bakit [-c|--compress] [-d|--dest DIR] <path>..."
    echo ""
    echo "Timestamped backup next to (or under) its destination:"
    echo "  <name>.<YYYYmmdd_HHMMSS>.bak       plain copy (default)"
    echo "  <name>.<YYYYmmdd_HHMMSS>.tar.gz    with --compress"
    echo ""
    echo "Options:"
    echo "  -c, --compress    Archive folders/large items as .tar.gz"
    echo "  -d, --dest DIR    Place backups in DIR (created if missing)"
    echo "  -h, --help        Show this help"
end

function bakit -d "Timestamped backup of files or directories"
    argparse h/help c/compress 'd/dest=' -- $argv
    or return 1

    if set -q _flag_help
        __bakit_help
        return 0
    end
    if test (count $argv) -eq 0
        __bakit_help >&2
        return 1
    end

    set -l ts (date +%Y%m%d_%H%M%S)
    set -l dest ""
    if set -q _flag_dest
        set dest "$_flag_dest/"
        mkdir -p -- "$_flag_dest"; or return 1
    end

    set -l total (count $argv)
    set -l ok 0
    set -l fail 0
    for item in $argv
        if not test -e $item
            set_color $gruvbox_yellow
            echo "⚠ not found, skipping: $item" >&2
            set_color normal
            set fail (math $fail + 1)
            continue
        end

        set -l target
        if set -q _flag_compress
            set target "$dest"(path basename $item)"."$ts".tar.gz"
        else
            set target "$dest"(path basename $item)"."$ts".bak"
        end

        set_color $gruvbox_blue
        echo "📦 '$item' → '$target'"
        set_color normal

        if set -q _flag_compress
            tar -czf "$target" -C (path dirname $item) (path basename $item)
        else
            cp -a -- "$item" "$target"
        end

        if test $status -eq 0
            set ok (math $ok + 1)
            set_color $gruvbox_green
            echo "  ✓ backed up"
            set_color normal
        else
            set fail (math $fail + 1)
            rm -f -- "$target"
            set_color $gruvbox_red
            echo "  ✗ failed (partial output removed)" >&2
            set_color normal
        end
    end

    if test $total -gt 1
        set_color $gruvbox_aqua
        echo "◆ $ok backed up, $fail failed"
        set_color normal
    end
    test $fail -eq 0
end

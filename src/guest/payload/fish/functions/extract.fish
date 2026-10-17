function __extract_help
    echo "Usage: extract <archive> [more...]"
    echo ""
    echo "  tar.* / zip  → unpacked into a folder named after the archive"
    echo "                 (bomb protection: contents never spill into cwd)"
    echo "  .gz, .bz2, .xz → decompressed in place, archive kept (-k)"
    echo "  -h, --help     Show this help"
end

function extract -d "Extract tar/zip into a derived folder, decompress gz/bz2/xz in place"
    argparse h/help -- $argv
    or return 1

    if set -q _flag_help
        __extract_help
        return 0
    end
    if test (count $argv) -eq 0
        __extract_help >&2
        return 1
    end

    set -l total (count $argv)
    set -l ok 0
    set -l fail 0
    for a in $argv
        if not test -f $a
            set_color $gruvbox_yellow
            echo "⚠ not a file, skipping: $a" >&2
            set_color normal
            set fail (math $fail + 1)
            continue
        end

        set -l dir (string replace -r \
            '\.(tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar|zip)$' '' -- $a)
        set -l used_dir 0
        set -l where "in place"

        switch "$a"
            case '*.tar.gz' '*.tgz' '*.tar.bz2' '*.tbz2' '*.tar.xz' '*.txz' '*.tar'
                set used_dir 1
                set where "$dir/"
                mkdir -p -- "$dir"; and tar -xf "$a" -C "$dir"
            case '*.zip'
                set used_dir 1
                set where "$dir/"
                mkdir -p -- "$dir"; and unzip -q "$a" -d "$dir"
            case '*.gz'
                gunzip -k -- "$a"
            case '*.bz2'
                bunzip2 -k -- "$a"
            case '*.xz'
                unxz -k -- "$a"
            case '*'
                set_color $gruvbox_yellow
                echo "⚠ unknown format: $a" >&2
                set_color normal
                set fail (math $fail + 1)
                continue
        end

        if test $status -eq 0
            set ok (math $ok + 1)
            set_color $gruvbox_green
            echo "✓ $a → $where"
            set_color normal
        else
            set fail (math $fail + 1)
            if test $used_dir -eq 1
                # keep cleanup honest: remove a failed, still-empty folder
                if test -d "$dir"; and test (count (command ls -A "$dir")) -eq 0
                    rmdir -- "$dir"
                end
            end
            set_color $gruvbox_red
            echo "✗ failed: $a" >&2
            set_color normal
        end
    end

    if test $total -gt 1
        set_color $gruvbox_aqua
        echo "◆ $ok extracted, $fail failed"
        set_color normal
    end
    test $fail -eq 0
end

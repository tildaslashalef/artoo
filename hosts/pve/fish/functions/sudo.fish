function sudo -d "Proxmox has no sudo: root runs the command directly"
    if test (id -u) -ne 0
        echo "sudo: not installed on this host; log in as root" >&2
        return 1
    end
    $argv
end

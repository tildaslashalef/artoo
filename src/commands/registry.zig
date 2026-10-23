//! The command tree. A command appears here only once it works (SPEC §3.3).

const cli = @import("../cli.zig");

pub const root = cli.group("artoo", "Home-lab CLI for a Proxmox VE host, a UniFi gateway and a Cloudflare zone.", &.{
    @import("auth.zig").group,
    @import("config.zig").group,
    @import("doctor.zig").command,
    @import("gw.zig").group,
    @import("dns.zig").group,
    @import("cf.zig").group,
    @import("host.zig").group,
    @import("storage.zig").group,
    @import("task.zig").group,
    @import("vm.zig").group,
    @import("image.zig").group,
    @import("template.zig").group,
    @import("edge.zig").group,
    @import("svc.zig").group,
    @import("router.zig").group,
    @import("watch.zig").group,
    @import("status.zig").command,
    @import("update.zig").command,
    cli.leaf(@import("completion.zig").completion),
    cli.leaf(@import("completion.zig").internal),
});

test {
    _ = @import("config.zig");
    _ = @import("auth.zig");
    _ = @import("doctor.zig");
    _ = @import("gw.zig");
    _ = @import("gw_write.zig");
    _ = @import("dns.zig");
    _ = @import("cf.zig");
    _ = @import("../cloudflare/client.zig");
    _ = @import("../cloudflare/dns.zig");
    _ = @import("../cloudflare/tunnel.zig");
    _ = @import("../exposure.zig");
    _ = @import("../unifi/dns.zig");
    _ = @import("../unifi/classic.zig");
    _ = @import("../guest/names.zig");
    _ = @import("../edge/files.zig");
    _ = @import("../watch/files.zig");
    _ = @import("../watch/grafana.zig");
    _ = @import("edge.zig");
    _ = @import("svc.zig");
    _ = @import("cf_tunnel.zig");
    _ = @import("router.zig");
    _ = @import("watch.zig");
    _ = @import("completion.zig");
    _ = @import("../unifi/body.zig");
    _ = @import("../pve/client.zig");
    _ = @import("../pve/task.zig");
    _ = @import("../pve/vm.zig");
    _ = @import("host.zig");
    _ = @import("storage.zig");
    _ = @import("task.zig");
    _ = @import("vm.zig");
    _ = @import("vm_life.zig");
    _ = @import("vm_new.zig");
    _ = @import("vm_ssh.zig");
    _ = @import("../guest/ssh_config.zig");
    _ = @import("../pve/agent.zig");
    _ = @import("../guest/known_hosts.zig");
    _ = @import("image.zig");
    _ = @import("template.zig");
    _ = @import("../pve/ssh.zig");
    _ = @import("../guest/image.zig");
    _ = @import("../guest/vendor.zig");
    _ = @import("status.zig");
    _ = @import("update.zig");
    _ = @import("../unifi/client.zig");
    _ = @import("../unifi/catalog.zig");
    _ = @import("../unifi/view.zig");
    _ = @import("../unifi/spec.zig");
}

const std = @import("std");
const version_tag = @import("src/version_tag.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", version(b));

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root.addOptions("build_options", options);

    const exe = b.addExecutable(.{ .name = "artoo", .root_module = root });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run artoo");
    run_step.dependOn(&run_cmd.step);

    // Offline unit/behavior tests: colocated `test` blocks reachable from main.
    const tests = b.addTest(.{ .root_module = root });
    const test_step = b.step("test", "Run offline tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const fmt = b.addFmt(.{ .paths = &.{ b.path("build.zig"), b.path("build.zig.zon"), b.path("src") }, .check = true });
    const fmt_step = b.step("fmt", "Check formatting");
    fmt_step.dependOn(&fmt.step);

    // SPEC §12: the Linux client builds must always compile.
    const cross_step = b.step("cross", "Compile for x86_64-linux and aarch64-linux");
    for ([_]std.Target.Cpu.Arch{ .x86_64, .aarch64 }) |arch| {
        const cross = b.addExecutable(.{
            .name = "artoo",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = b.resolveTargetQuery(.{ .cpu_arch = arch, .os_tag = .linux }),
                .optimize = optimize,
            }),
        });
        cross.root_module.addOptions("build_options", options);
        cross_step.dependOn(&cross.step);
        // Compile (not run) the tests too, so code not yet reachable from
        // main is still checked for Linux.
        const cross_tests = b.addTest(.{ .root_module = cross.root_module });
        cross_step.dependOn(&cross_tests.step);
    }
}

/// `artoo --version` (docs/RELEASING.md §1): derived from the nearest
/// annotated release tag by `git describe` (src/version_tag.zig) — the
/// tag's version at the tag, the next version as a dev build after it.
/// `-Dversion` overrides it for a source tree without Git history.
fn version(b: *std.Build) []const u8 {
    if (b.option([]const u8, "version", "Version to report instead of the one derived from Git tags")) |v| return v;
    // Git is read at configure time, which Zig 0.17 caches: without this,
    // every later build reported the commit of the first one.
    b.graph.poisonCache();
    var code: u8 = 0;
    const out = b.runAllowFail(&.{ "git", "describe", "--match", "v[0-9]*", "--long", "--abbrev=7", "HEAD" }, &code, .ignore) catch return version_tag.unknown;
    if (code != 0) return version_tag.unknown;
    return (version_tag.fromDescribe(b.allocator, out) catch null) orelse version_tag.unknown;
}

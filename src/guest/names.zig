//! Guest names (SPEC §9.1): one DNS label per guest, from a curated list
//! — Star Wars planets and moons, Lord of the Rings places — or any other
//! valid label. Purpose lives in the `role-…` tag, not in the name.

const std = @import("std");
const Io = std.Io;

/// Star Wars planets and moons.
pub const star_wars = [_][]const u8{
    "abafar",    "ahch-to",      "ajan-kloss", "aldhani",   "alderaan",    "anaxes",   "atollon",
    "batuu",     "bespin",       "bogano",     "bracca",    "cantonica",   "carlac",   "cato-neimoidia",
    "chandrila", "christophsis", "corellia",   "crait",     "csilla",      "dagobah",  "dantooine",
    "dathomir",  "eadu",         "endor",      "exegol",    "felucia",     "ferrix",   "florrum",
    "fondor",    "garel",        "geonosis",   "hosnian",   "hoth",        "ilum",     "iridonia",
    "jakku",     "jedha",        "kashyyyk",   "kef-bir",   "kessel",      "kijimi",   "koboh",
    "kuat",      "lothal",       "malachor",   "malastare", "mandalore",   "mimban",   "mon-cala",
    "mortis",    "mustafar",     "mygeeto",    "naboo",     "nal-hutta",   "nevarro",  "niamos",
    "onderon",   "ord-mantell",  "ossus",      "pasaana",   "polis-massa", "raxus",    "rishi",
    "rodia",     "ryloth",       "saleucami",  "savareen",  "scarif",      "serenno",  "sorgan",
    "sullust",   "takodana",     "tatooine",   "toydaria",  "trandosha",   "tython",   "umbara",
    "utapau",    "vandor",       "wobani",     "yavin",     "zeffo",       "zygerria",
};

/// Places of Middle-earth.
pub const middle_earth = [_][]const u8{
    "amon-hen",     "amon-sul", "anduin",         "arnor",        "barad-dur",   "belfalas",   "bree",
    "buckland",     "bywater",  "caras-galadhon", "cirith-ungol", "dale",        "dol-amroth", "dunharrow",
    "dunland",      "edoras",   "erebor",         "erech",        "eregion",     "eriador",    "esgaroth",
    "fangorn",      "fornost",  "gondolin",       "gondor",       "grey-havens", "harad",      "helms-deep",
    "hobbiton",     "isengard", "ithilien",       "khazad-dum",   "lebennin",    "lindon",     "lothlorien",
    "minas-tirith", "mirkwood", "mordor",         "moria",        "numenor",     "orthanc",    "osgiliath",
    "pelargir",     "rauros",   "rhun",           "rivendell",    "rohan",       "shire",      "tharbad",
    "umbar",        "valinor",  "weathertop",
};

/// Never a guest name: generic words for the protected infrastructure
/// (SPEC §9.6). The lab's own host and equipment names come from
/// `guests.reserved_names` and `pve.node` (exposure.zig).
pub const reserved = [_][]const u8{ "pve", "proxmox", "unifi", "gateway" };

pub const max_len = 40;

/// One lowercase DNS label: letter first; letters, digits and single
/// hyphens; no trailing hyphen; 2–40 characters.
pub fn valid(s: []const u8) bool {
    if (s.len < 2 or s.len > max_len or !std.ascii.isLower(s[0]) or s[s.len - 1] == '-') return false;
    for (s) |ch| if (!(std.ascii.isLower(ch) or std.ascii.isDigit(ch) or ch == '-')) return false;
    return std.mem.find(u8, s, "--") == null;
}

pub fn isReserved(s: []const u8) bool {
    for (reserved) |r| if (std.mem.eql(u8, r, s)) return true;
    return false;
}

/// Every curated name, in list order.
pub const all = star_wars ++ middle_earth;

/// A random curated name not in `used`; null when every one is taken.
pub fn pick(io: Io, used: []const []const u8) Io.RandomSecureError!?[]const u8 {
    var free: [all.len][]const u8 = undefined;
    var n: usize = 0;
    outer: for (all) |name| {
        for (used) |u| if (std.ascii.eqlIgnoreCase(u, name)) continue :outer;
        free[n] = name;
        n += 1;
    }
    if (n == 0) return null;
    var raw: [8]u8 = undefined;
    try Io.randomSecure(io, &raw);
    return free[std.mem.readInt(u64, &raw, .little) % n];
}

const testing = std.testing;

test "curated names are valid, unique and never reserved" {
    for (all, 0..) |name, i| {
        if (!valid(name) or isReserved(name)) {
            std.debug.print("bad curated name: {s}\n", .{name});
            return error.TestUnexpectedResult;
        }
        for (all[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, name, other));
    }
    try testing.expect(all.len >= 120);
}

test "valid" {
    for ([_][]const u8{ "naboo", "helms-deep", "web01", "k8s-a" }) |s| try testing.expect(valid(s));
    for ([_][]const u8{ "Naboo", "1naboo", "naboo-", "na--boo", "n", "na_boo", "naboo.lab" }) |s| try testing.expect(!valid(s));
}

test "pick: skips used names, null when none is left" {
    var used: [all.len][]const u8 = undefined;
    @memcpy(used[0 .. all.len - 1], all[1..]);
    try testing.expectEqualStrings(all[0], (try pick(testing.io, used[0 .. all.len - 1])).?);
    used[all.len - 1] = all[0];
    try testing.expect((try pick(testing.io, &used)) == null);
}

//! Pluggable Kad-DHT record validators (#198).
//!
//! Embedders register prefix → callback pairs; [`RecordStore.putValue`] consults
//! the registry before persisting opaque `PUT_VALUE` payloads.

const std = @import("std");

pub const ValidationResult = enum {
    accept,
    reject,
    ignore,
};

pub const ValidateFn = *const fn (
    ctx: ?*anyopaque,
    key: []const u8,
    value: []const u8,
    existing: ?[]const u8,
) ValidationResult;

const Entry = struct {
    prefix: []const u8,
    validate: ValidateFn,
    ctx: ?*anyopaque = null,
};

pub const Stats = struct {
    accepted: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{
            .allocator = allocator,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *Registry) void {
        for (self.entries.items) |e| self.allocator.free(e.prefix);
        self.entries.deinit(self.allocator);
        self.* = undefined;
        self.entries = .empty;
    }

    pub fn register(
        self: *Registry,
        prefix: []const u8,
        callback: ValidateFn,
        ctx: ?*anyopaque,
    ) std.mem.Allocator.Error!void {
        try self.entries.append(self.allocator, .{
            .prefix = try self.allocator.dupe(u8, prefix),
            .validate = callback,
            .ctx = ctx,
        });
    }

    pub fn validate(
        self: *const Registry,
        key: []const u8,
        value: []const u8,
        existing: ?[]const u8,
    ) ValidationResult {
        var best: ?*const Entry = null;
        for (self.entries.items) |*e| {
            if (!std.mem.startsWith(u8, key, e.prefix)) continue;
            if (best == null or e.prefix.len > best.?.prefix.len) best = e;
        }
        if (best) |e| return e.validate(e.ctx, key, value, existing);
        return .accept;
    }
};

pub fn recordValidationOutcome(
    stats: ?*Stats,
    result: ValidationResult,
) ValidationResult {
    if (stats) |s| switch (result) {
        .accept => s.accepted += 1,
        .reject => s.rejected += 1,
        .ignore => s.ignored += 1,
    };
    return result;
}

test "registry longest prefix wins" {
    const a = std.testing.allocator;
    var reg = Registry.init(a);
    defer reg.deinit();

    const Ctx = struct {
        fn accept(_: ?*anyopaque, _: []const u8, _: []const u8, _: ?[]const u8) ValidationResult {
            return .accept;
        }
        fn reject(_: ?*anyopaque, _: []const u8, _: []const u8, _: ?[]const u8) ValidationResult {
            return .reject;
        }
    };

    try reg.register("/ipns/", Ctx.accept, null);
    try reg.register("/ipns/special/", Ctx.reject, null);
    try std.testing.expect(reg.validate("/ipns/foo", "v", null) == .accept);
    try std.testing.expect(reg.validate("/ipns/special/x", "v", null) == .reject);
}

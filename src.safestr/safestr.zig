//! libsafestr — bounds-checked C string primitives, implemented in Zig.
//!
//! Every function takes the destination size explicitly, always
//! NUL-terminates on success, and reports truncation instead of hiding it.
//! The API is C ABI (see safestr.h) so the existing C tools can link it.

const std = @import("std");

pub const SstrStatus = enum(c_int) {
    ok = 0, // operation completed, nothing truncated
    truncated = 1, // output truncated; result is still NUL-terminated
    invalid = 2, // bad arguments (NULL pointer or zero size)
};

inline fn status(s: SstrStatus) c_int {
    return @intFromEnum(s);
}

/// Bounded strlen: returns the length of `s`, scanning at most `max_len`
/// bytes. Returns `max_len` if no NUL is found within the limit.
export fn sstr_len(s: ?[*:0]const u8, max_len: usize) usize {
    const p = s orelse return 0;
    var i: usize = 0;
    while (i < max_len and p[i] != 0) : (i += 1) {}
    return i;
}

/// Copy `src` into `dst` (size `dst_size`), always NUL-terminating.
/// Reports .truncated if `src` did not fit.
export fn sstr_copy(dst: ?[*]u8, dst_size: usize, src: ?[*:0]const u8) c_int {
    const d = dst orelse return status(.invalid);
    const s = src orelse return status(.invalid);
    if (dst_size == 0) return status(.invalid);
    const n = sstr_len(s, std.math.maxInt(usize));
    const want = n + 1;
    if (want <= dst_size) {
        @memcpy(d[0..want], s[0..want]);
        return status(.ok);
    }
    @memcpy(d[0 .. dst_size - 1], s[0 .. dst_size - 1]);
    d[dst_size - 1] = 0;
    return status(.truncated);
}

/// Append `src` to the NUL-terminated string in `dst` (size `dst_size`).
/// Reports .truncated if the result did not fit.
export fn sstr_cat(dst: ?[*]u8, dst_size: usize, src: ?[*:0]const u8) c_int {
    const d = dst orelse return status(.invalid);
    const s = src orelse return status(.invalid);
    if (dst_size == 0) return status(.invalid);
    const cur = sstr_len(@ptrCast(d), dst_size);
    if (cur == dst_size) return status(.invalid); // dst not NUL-terminated
    return sstr_copy(d + cur, dst_size - cur, s);
}

/// Copy at most `src_len` bytes of `src` (which need not be
/// NUL-terminated) into `dst`, always NUL-terminating.
export fn sstr_copy_n(dst: ?[*]u8, dst_size: usize, src: ?[*]const u8, src_len: usize) c_int {
    const d = dst orelse return status(.invalid);
    const s = src orelse return status(.invalid);
    if (dst_size == 0) return status(.invalid);
    const n = @min(src_len, sstr_len(@ptrCast(s), src_len));
    const want = n + 1;
    if (want <= dst_size) {
        @memcpy(d[0..n], s[0..n]);
        d[n] = 0;
        return status(.ok);
    }
    @memcpy(d[0 .. dst_size - 1], s[0 .. dst_size - 1]);
    d[dst_size - 1] = 0;
    return status(.truncated);
}

// -------------------------------------------------------------------------
// tests
// -------------------------------------------------------------------------

test "sstr_len basic and bounded" {
    try std.testing.expectEqual(@as(usize, 5), sstr_len("hello", 100));
    try std.testing.expectEqual(@as(usize, 3), sstr_len("hello", 3));
    try std.testing.expectEqual(@as(usize, 0), sstr_len(null, 10));
}

test "sstr_copy exact, truncation, invalid" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(status(.ok), sstr_copy(&buf, buf.len, "abc"));
    try std.testing.expectEqualStrings("abc", std.mem.sliceTo(&buf, 0));

    try std.testing.expectEqual(status(.truncated), sstr_copy(&buf, buf.len, "0123456789"));
    try std.testing.expectEqualStrings("0123456", std.mem.sliceTo(&buf, 0));

    try std.testing.expectEqual(status(.invalid), sstr_copy(&buf, 0, "abc"));
    try std.testing.expectEqual(status(.invalid), sstr_copy(null, 8, "abc"));
}

test "sstr_cat appends and truncates" {
    var buf: [8]u8 = undefined;
    _ = sstr_copy(&buf, buf.len, "abc");
    try std.testing.expectEqual(status(.ok), sstr_cat(&buf, buf.len, "def"));
    try std.testing.expectEqualStrings("abcdef", std.mem.sliceTo(&buf, 0));
    try std.testing.expectEqual(status(.truncated), sstr_cat(&buf, buf.len, "XYZ"));
    try std.testing.expectEqualStrings("abcdefX", std.mem.sliceTo(&buf, 0));
}

test "sstr_copy_n handles unterminated sources" {
    var buf: [8]u8 = undefined;
    const raw = [_]u8{ 'a', 'b', 'c' };
    try std.testing.expectEqual(status(.ok), sstr_copy_n(&buf, buf.len, &raw, raw.len));
    try std.testing.expectEqualStrings("abc", std.mem.sliceTo(&buf, 0));
    try std.testing.expectEqual(status(.truncated), sstr_copy_n(&buf, 2, &raw, raw.len));
}

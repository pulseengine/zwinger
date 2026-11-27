//! The path rules every backend decision rests on, written once and checked by two provers.
//!
//! The code inside `verus!` is the shipped code. A normal build erases the specs and proofs and
//! compiles the rest as plain Rust. Verus (Z3) proves the properties below for byte strings of
//! any length (`cargo verus verify`, CI job "Verus proofs"). Kani (CBMC) checks the same
//! functions, through the thin wrappers in `profile` and `linux`, exhaustively for short paths.
//! Two solvers with different trusted bases over one implementation: a gap in one is not
//! silently shared by the other.
//!
//! Proven, unbounded:
//! - `within_bytes` computes `spec_within` exactly (any bytes);
//! - two ancestors of a normal path are nested (`lemma_ancestors_nested`);
//! - `within` is transitive on normal paths (`lemma_within_transitive`).

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

/// `inner` equals `outer` or lies beneath it: `outer` is empty (no components, a prefix of
/// everything), or the root (which contains every absolute path), or a byte prefix of `inner`
/// that ends at a component boundary.
pub open spec fn spec_within(inner: Seq<u8>, outer: Seq<u8>) -> bool {
    if outer.len() == 0 {
        true
    } else if outer =~= seq![b'/'] {
        inner.len() > 0 && inner[0] == b'/'
    } else {
        outer.len() <= inner.len()
            && inner.subrange(0, outer.len() as int) =~= outer
            && (inner.len() == outer.len() || inner[outer.len() as int] == b'/')
    }
}

/// A path in the normal form `normalize` and `canonicalize` produce: absolute, and no trailing
/// separator except the root itself.
pub open spec fn normal(p: Seq<u8>) -> bool {
    p.len() >= 1 && p[0] == b'/' && (p.len() == 1 || p[p.len() - 1] != b'/')
}

/// `spec_within`, computed. The shipped `profile::within` is this function on the paths' bytes.
// `len() == 0` rather than `is_empty()`: Verus specifies slice `len`.
#[allow(clippy::len_zero)]
pub fn within_bytes(inner: &[u8], outer: &[u8]) -> (r: bool)
    ensures
        r == spec_within(inner@, outer@),
{
    if outer.len() == 0 {
        return true;
    }
    if outer.len() == 1 && outer[0] == b'/' {
        assert(outer@ =~= seq![b'/']);
        return inner.len() > 0 && inner[0] == b'/';
    }
    assert(!(outer@ =~= seq![b'/'])) by {
        if outer@ =~= seq![b'/'] {
            assert(outer@.len() == 1 && outer@[0] == b'/');
        }
    }
    if outer.len() > inner.len() {
        return false;
    }
    let mut k: usize = 0;
    while k < outer.len()
        invariant
            k <= outer.len(),
            outer.len() <= inner.len(),
            forall|j: int| 0 <= j < k ==> inner@[j] == outer@[j],
        decreases outer.len() - k,
    {
        if inner[k] != outer[k] {
            assert(inner@.subrange(0, outer.len() as int)[k as int] != outer@[k as int]);
            return false;
        }
        k += 1;
    }
    assert(inner@.subrange(0, outer.len() as int) =~= outer@);
    inner.len() == outer.len() || inner[outer.len()] == b'/'
}

/// Two ancestors of the same normal path are nested one in the other. This is what lets rules
/// that compare only grants with denied paths speak for every path beneath them.
pub proof fn lemma_ancestors_nested(x: Seq<u8>, a: Seq<u8>, b: Seq<u8>)
    requires
        normal(x),
        normal(a),
        normal(b),
        spec_within(x, a),
        spec_within(x, b),
    ensures
        spec_within(a, b) || spec_within(b, a),
{
    let ra = a =~= seq![b'/'];
    let rb = b =~= seq![b'/'];
    if rb {
        assert(spec_within(a, b));
    } else if ra {
        assert(spec_within(b, a));
    } else if a.len() <= b.len() {
        // a and b are both prefixes of x, so a is a prefix of b.
        assert forall|j: int| 0 <= j < a.len() implies b[j] == a[j] by {
            assert(x.subrange(0, a.len() as int)[j] == a[j]);
            assert(x.subrange(0, b.len() as int)[j] == b[j]);
        }
        assert(b.subrange(0, a.len() as int) =~= a);
        if a.len() < b.len() {
            assert(x.subrange(0, b.len() as int)[a.len() as int] == b[a.len() as int]);
        }
        assert(spec_within(b, a));
    } else {
        assert forall|j: int| 0 <= j < b.len() implies a[j] == b[j] by {
            assert(x.subrange(0, a.len() as int)[j] == a[j]);
            assert(x.subrange(0, b.len() as int)[j] == b[j]);
        }
        assert(a.subrange(0, b.len() as int) =~= b);
        assert(x.subrange(0, a.len() as int)[b.len() as int] == a[b.len() as int]);
        assert(spec_within(a, b));
    }
}

/// `within` is transitive on normal paths.
pub proof fn lemma_within_transitive(x: Seq<u8>, a: Seq<u8>, b: Seq<u8>)
    requires
        normal(x),
        normal(a),
        normal(b),
        spec_within(x, a),
        spec_within(a, b),
    ensures
        spec_within(x, b),
{
    if b =~= seq![b'/'] {
        assert(spec_within(x, b));
    } else if a =~= seq![b'/'] {
        // b is within the root and normal and not the root: then b would have to be a prefix
        // of "/" ending at a boundary, which only "/" is.
        assert(b.len() <= a.len());
        assert(b.len() == 1);
        assert(b[0] == b'/');
        assert(b =~= seq![b'/']);
    } else {
        assert forall|j: int| 0 <= j < b.len() implies x[j] == b[j] by {
            assert(a.subrange(0, b.len() as int)[j] == b[j]);
            assert(x.subrange(0, a.len() as int)[j] == a[j]);
        }
        assert(x.subrange(0, b.len() as int) =~= b);
        if b.len() < a.len() {
            assert(x.subrange(0, a.len() as int)[b.len() as int] == a[b.len() as int]);
        }
        assert(spec_within(x, b));
    }
}


/// One grant or denied path for the carve-out rules: as the profile stated it, and as the
/// kernel will reach it. `is_read` marks a grant from `read`/`read_if_present`, the only kind a
/// stated exception inside a `deny_read` may be.
pub struct Entry<'a> {
    pub is_read: bool,
    pub stated: &'a [u8],
    pub resolved: &'a [u8],
}

/// Which carve-out rule a profile breaks: the rule, and the deny and grant entries by index
/// (`write_grant` says which grant list `grant` indexes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Violation {
    pub deny_inside_grant: bool,
    pub deny_write: bool,
    pub deny: usize,
    pub write_grant: bool,
    pub grant: usize,
}

/// A read stated inside a deny_read: one public key in a secrets directory.
pub open spec fn stated_exception(g: Entry, d: Entry) -> bool {
    g.is_read && spec_within(g.stated@, d.stated@) && !spec_within(d.stated@, g.stated@)
}

/// A grant `g` and a deny_read `d` are compatible: `g` does not cover `d`, and reaches into `d`
/// only as a stated exception.
pub open spec fn read_rule_ok(g: Entry, d: Entry) -> bool {
    !spec_within(d.resolved@, g.resolved@)
        && (!spec_within(g.resolved@, d.resolved@) || stated_exception(g, d))
}

/// A write grant `g` and a deny_write `d` are disjoint.
pub open spec fn write_rule_ok(g: Entry, d: Entry) -> bool {
    !spec_within(d.resolved@, g.resolved@) && !spec_within(g.resolved@, d.resolved@)
}

pub open spec fn deny_read_ok(read: Seq<Entry>, write: Seq<Entry>, d: Entry) -> bool {
    (forall|j: int| 0 <= j < read.len() ==> read_rule_ok(#[trigger] read[j], d))
        && (forall|j: int| 0 <= j < write.len() ==> read_rule_ok(#[trigger] write[j], d))
}

pub open spec fn deny_write_ok(write: Seq<Entry>, d: Entry) -> bool {
    forall|j: int| 0 <= j < write.len() ==> write_rule_ok(#[trigger] write[j], d)
}

/// Every pair the carve-out rules compare is compatible.
pub open spec fn carve_ok(read: Seq<Entry>, write: Seq<Entry>, dr: Seq<Entry>, dw: Seq<Entry>) -> bool {
    (forall|i: int| 0 <= i < dr.len() ==> deny_read_ok(read, write, #[trigger] dr[i]))
        && (forall|i: int| 0 <= i < dw.len() ==> deny_write_ok(write, #[trigger] dw[i]))
}

/// The carve-out rules, separate from the filesystem and allocation-free. Landlock only
/// grants, so a profile is enforceable as written exactly when no granted tree covers a denied
/// path, and no grant reaches into a denied tree except a read stated inside a deny_read. The
/// shipped `linux::first_carve_violation` is this function on the paths' bytes.
pub fn first_carve_violation_bytes(
    read: &[Entry],
    write: &[Entry],
    deny_read: &[Entry],
    deny_write: &[Entry],
) -> (r: Option<Violation>)
    ensures
        r.is_none() ==> carve_ok(read@, write@, deny_read@, deny_write@),
{
    let mut di: usize = 0;
    while di < deny_read.len()
        invariant
            di <= deny_read.len(),
            forall|i: int| 0 <= i < di ==> deny_read_ok(read@, write@, #[trigger] deny_read@[i]),
        decreases deny_read.len() - di,
    {
        let d = &deny_read[di];
        let mut gi: usize = 0;
        while gi < read.len()
            invariant
                di < deny_read.len(),
                d == deny_read@[di as int],
                gi <= read.len(),
                forall|j: int| 0 <= j < gi ==> read_rule_ok(#[trigger] read@[j], *d),
            decreases read.len() - gi,
        {
            let g = &read[gi];
            if within_bytes(d.resolved, g.resolved) {
                return Some(Violation { deny_inside_grant: true, deny_write: false, deny: di, write_grant: false, grant: gi });
            }
            let stated = g.is_read && within_bytes(g.stated, d.stated) && !within_bytes(d.stated, g.stated);
            if within_bytes(g.resolved, d.resolved) && !stated {
                return Some(Violation { deny_inside_grant: false, deny_write: false, deny: di, write_grant: false, grant: gi });
            }
            gi += 1;
        }
        let mut gi: usize = 0;
        while gi < write.len()
            invariant
                di < deny_read.len(),
                d == deny_read@[di as int],
                gi <= write.len(),
                forall|j: int| 0 <= j < read.len() ==> read_rule_ok(#[trigger] read@[j], *d),
                forall|j: int| 0 <= j < gi ==> read_rule_ok(#[trigger] write@[j], *d),
            decreases write.len() - gi,
        {
            let g = &write[gi];
            if within_bytes(d.resolved, g.resolved) {
                return Some(Violation { deny_inside_grant: true, deny_write: false, deny: di, write_grant: true, grant: gi });
            }
            let stated = g.is_read && within_bytes(g.stated, d.stated) && !within_bytes(d.stated, g.stated);
            if within_bytes(g.resolved, d.resolved) && !stated {
                return Some(Violation { deny_inside_grant: false, deny_write: false, deny: di, write_grant: true, grant: gi });
            }
            gi += 1;
        }
        di += 1;
    }
    let mut di: usize = 0;
    while di < deny_write.len()
        invariant
            di <= deny_write.len(),
            forall|i: int| 0 <= i < deny_read.len() ==> deny_read_ok(read@, write@, #[trigger] deny_read@[i]),
            forall|i: int| 0 <= i < di ==> deny_write_ok(write@, #[trigger] deny_write@[i]),
        decreases deny_write.len() - di,
    {
        let d = &deny_write[di];
        let mut gi: usize = 0;
        while gi < write.len()
            invariant
                di < deny_write.len(),
                d == deny_write@[di as int],
                gi <= write.len(),
                forall|j: int| 0 <= j < gi ==> write_rule_ok(#[trigger] write@[j], *d),
            decreases write.len() - gi,
        {
            let g = &write[gi];
            if within_bytes(d.resolved, g.resolved) {
                return Some(Violation { deny_inside_grant: true, deny_write: true, deny: di, write_grant: true, grant: gi });
            }
            if within_bytes(g.resolved, d.resolved) {
                return Some(Violation { deny_inside_grant: false, deny_write: true, deny: di, write_grant: true, grant: gi });
            }
            gi += 1;
        }
        di += 1;
    }
    None
}

/// REQ-ZW-008, unbounded: if the carve-out rules accept a profile whose resolved paths are in
/// normal form, then for every normal path x beneath a deny_read, no write grant covers x, and
/// a read grant covers x only as a read exception stated inside that deny_read; and for every
/// x beneath a deny_write, no write grant covers x. Landlock, which only grants, then denies x.
pub proof fn lemma_carve_sound(
    read: Seq<Entry>,
    write: Seq<Entry>,
    dr: Seq<Entry>,
    dw: Seq<Entry>,
    x: Seq<u8>,
)
    requires
        carve_ok(read, write, dr, dw),
        normal(x),
        forall|j: int| 0 <= j < read.len() ==> normal(#[trigger] read[j].resolved@),
        forall|j: int| 0 <= j < write.len() ==> normal(#[trigger] write[j].resolved@),
        forall|i: int| 0 <= i < dr.len() ==> normal(#[trigger] dr[i].resolved@),
        forall|i: int| 0 <= i < dw.len() ==> normal(#[trigger] dw[i].resolved@),
    ensures
        forall|i: int, j: int|
            0 <= i < dr.len() && 0 <= j < write.len() && spec_within(x, dr[i].resolved@)
                ==> !spec_within(x, #[trigger] write[j].resolved@) || stated_exception(write[j], #[trigger] dr[i]),
        forall|i: int, j: int|
            0 <= i < dr.len() && 0 <= j < read.len() && spec_within(x, dr[i].resolved@)
                ==> !spec_within(x, #[trigger] read[j].resolved@) || stated_exception(read[j], #[trigger] dr[i]),
        forall|i: int, j: int|
            0 <= i < dw.len() && 0 <= j < write.len() && spec_within(x, dw[i].resolved@)
                ==> !spec_within(x, #[trigger] write[j].resolved@) && #[trigger] dw[i] == dw[i],
{
    assert forall|i: int, j: int|
        0 <= i < dr.len() && 0 <= j < write.len() && spec_within(x, dr[i].resolved@)
            implies !spec_within(x, #[trigger] write[j].resolved@) || stated_exception(write[j], #[trigger] dr[i]) by {
        assert(deny_read_ok(read, write, dr[i]));
        assert(read_rule_ok(write[j], dr[i]));
        if spec_within(x, write[j].resolved@) {
            lemma_ancestors_nested(x, dr[i].resolved@, write[j].resolved@);
        }
    }
    assert forall|i: int, j: int|
        0 <= i < dr.len() && 0 <= j < read.len() && spec_within(x, dr[i].resolved@)
            implies !spec_within(x, #[trigger] read[j].resolved@) || stated_exception(read[j], #[trigger] dr[i]) by {
        assert(deny_read_ok(read, write, dr[i]));
        assert(read_rule_ok(read[j], dr[i]));
        if spec_within(x, read[j].resolved@) {
            lemma_ancestors_nested(x, dr[i].resolved@, read[j].resolved@);
        }
    }
    assert forall|i: int, j: int|
        0 <= i < dw.len() && 0 <= j < write.len() && spec_within(x, dw[i].resolved@)
            implies !spec_within(x, #[trigger] write[j].resolved@) && #[trigger] dw[i] == dw[i] by {
        assert(deny_write_ok(write, dw[i]));
        assert(write_rule_ok(write[j], dw[i]));
        if spec_within(x, write[j].resolved@) {
            lemma_ancestors_nested(x, dw[i].resolved@, write[j].resolved@);
        }
    }
}


/// A grant keeps the execute right exactly when it lies at or beneath no noexec tree.
pub open spec fn spec_may_exec(grant: Seq<u8>, noexec: Seq<&[u8]>) -> bool {
    forall|n: int| 0 <= n < noexec.len() ==> !spec_within(grant, #[trigger] noexec[n]@)
}

/// No noexec tree lies strictly inside a grant.
pub open spec fn noexec_ok(grants: Seq<&[u8]>, noexec: Seq<&[u8]>) -> bool {
    forall|n: int, g: int|
        0 <= n < noexec.len() && 0 <= g < grants.len()
            ==> !(spec_within(#[trigger] noexec[n]@, #[trigger] grants[g]@) && !spec_within(grants[g]@, noexec[n]@))
}

/// `spec_may_exec`, computed. The shipped `linux::may_exec` is this function on the bytes.
pub fn may_exec_bytes(grant: &[u8], noexec: &[&[u8]]) -> (r: bool)
    ensures
        r == spec_may_exec(grant@, noexec@),
{
    let mut n: usize = 0;
    while n < noexec.len()
        invariant
            n <= noexec.len(),
            forall|k: int| 0 <= k < n ==> !spec_within(grant@, #[trigger] noexec@[k]@),
        decreases noexec.len() - n,
    {
        if within_bytes(grant, noexec[n]) {
            return false;
        }
        n += 1;
    }
    true
}

/// The first (noexec, grant) pair where the noexec tree lies strictly inside the grant. The
/// shipped `linux::first_noexec_violation` is this function on the bytes.
pub fn first_noexec_violation_bytes(grants: &[&[u8]], noexec: &[&[u8]]) -> (r: Option<(usize, usize)>)
    ensures
        r.is_none() ==> noexec_ok(grants@, noexec@),
{
    let mut n: usize = 0;
    while n < noexec.len()
        invariant
            n <= noexec.len(),
            forall|k: int, g: int|
                0 <= k < n && 0 <= g < grants.len()
                    ==> !(spec_within(#[trigger] noexec@[k]@, #[trigger] grants@[g]@) && !spec_within(grants@[g]@, noexec@[k]@)),
        decreases noexec.len() - n,
    {
        let mut g: usize = 0;
        while g < grants.len()
            invariant
                n < noexec.len(),
                g <= grants.len(),
                forall|k: int, h: int|
                    0 <= k < n && 0 <= h < grants.len()
                        ==> !(spec_within(#[trigger] noexec@[k]@, #[trigger] grants@[h]@) && !spec_within(grants@[h]@, noexec@[k]@)),
                forall|h: int|
                    0 <= h < g ==> !(spec_within(noexec@[n as int]@, #[trigger] grants@[h]@) && !spec_within(grants@[h]@, noexec@[n as int]@)),
            decreases grants.len() - g,
        {
            if within_bytes(noexec[n], grants[g]) && !within_bytes(grants[g], noexec[n]) {
                return Some((n, g));
            }
            g += 1;
        }
        n += 1;
    }
    None
}

/// REQ-ZW-013, unbounded: if the noexec rule accepts the grants and every path is normal, then
/// for every normal path x beneath a noexec tree, every grant covering x has lost execute.
/// Landlock allows execve only through a rule on an ancestor of x that carries the right.
pub proof fn lemma_noexec_sound(grants: Seq<&[u8]>, noexec: Seq<&[u8]>, x: Seq<u8>)
    requires
        noexec_ok(grants, noexec),
        normal(x),
        forall|g: int| 0 <= g < grants.len() ==> normal(#[trigger] grants[g]@),
        forall|n: int| 0 <= n < noexec.len() ==> normal(#[trigger] noexec[n]@),
    ensures
        forall|n: int, g: int|
            0 <= n < noexec.len() && 0 <= g < grants.len() && spec_within(x, #[trigger] noexec[n]@)
                && spec_within(x, #[trigger] grants[g]@)
                ==> !spec_may_exec(grants[g]@, noexec),
{
    assert forall|n: int, g: int|
        0 <= n < noexec.len() && 0 <= g < grants.len() && spec_within(x, #[trigger] noexec[n]@)
            && spec_within(x, #[trigger] grants[g]@)
            implies !spec_may_exec(grants[g]@, noexec) by {
        lemma_ancestors_nested(x, noexec[n]@, grants[g]@);
        assert(spec_within(grants[g]@, noexec[n]@));
    }
}

} // verus!

//! Differential engine: replays one operation sequence against two
//! [`KeyStore`]s (normally the Rust and C++ implementations) and reports the
//! first divergence in status code or output.
//!
//! The sequence is decoded from a byte string, so the same engine serves the
//! seeded tests (`tests/differential.rs`) and the fuzzer (`fuzz/`).
//!
//! Keys imported from the same bytes have the same ID on both sides, so every
//! output under them must be byte-identical. Generated keys differ per side;
//! the engine tracks them as pairs and compares statuses and lengths only.
use ccb::{KeyId, KeyStore, Status, NONCE_LEN};

/// Byte source; returns zeros once exhausted.
pub struct Src<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Src<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Src { data, pos: 0 }
    }
    pub fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.u8() as usize % xs.len()]
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.u8() as usize % (max + 1);
        (0..n).map(|_| self.u8()).collect()
    }
}

#[derive(Clone, Copy)]
struct Key {
    a: KeyId,
    b: KeyId,
    /// Same key bytes on both sides (so same ID and same outputs).
    det: bool,
}

/// A message sealed on both sides: (output a, output b, aad, key).
type Sealed = (Vec<u8>, Vec<u8>, Vec<u8>, Key);

#[derive(Default, Debug)]
pub struct Stats {
    pub ops: u64,
    /// [op][status index]: how often each op ended in each status.
    pub outcomes: [[u64; 12]; 11],
}

pub const OP_NAMES: [&str; 11] = [
    "import",
    "generate",
    "destroy",
    "wrap",
    "unwrap",
    "hmac_sign",
    "hmac_verify",
    "seal",
    "open",
    "hkdf",
    "cross_open",
];

fn idx(r: &ccb::Result<impl Sized>) -> usize {
    match r {
        Ok(_) => 0,
        Err(s) => (-(*s as i32)) as usize,
    }
}

const MATERIALS: [[u8; 32]; 4] = [[0x11; 32], [0x22; 32], [0x5a; 32], {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
}];

pub struct Engine<'s> {
    a: &'s mut dyn KeyStore,
    b: &'s mut dyn KeyStore,
    keys: Vec<Key>,
    blobs: Vec<(Vec<u8>, Vec<u8>, Key)>,           // (a, b, kek)
    sealed: Vec<Sealed>,
    pub stats: Stats,
    /// Restrict to ops a PKCS#11 token supports cheaply (no hkdf success path
    /// is possible there anyway; it still checks the Unsupported status).
    pub max_payload: usize,
}

impl<'s> Engine<'s> {
    pub fn new(a: &'s mut dyn KeyStore, b: &'s mut dyn KeyStore) -> Self {
        Engine { a, b, keys: vec![], blobs: vec![], sealed: vec![], stats: Stats::default(), max_payload: 64 }
    }

    fn key(&mut self, src: &mut Src) -> Key {
        // 1 in 8: an ID neither side has ever seen.
        if self.keys.is_empty() || src.u8() % 8 == 0 {
            let mut id = [0u8; 32];
            id[0] = src.u8();
            id[31] = 0xee;
            return Key { a: id, b: id, det: true };
        }
        self.keys[src.u8() as usize % self.keys.len()]
    }

    /// Runs ops until `src` is exhausted. Err describes the first divergence.
    pub fn run(&mut self, src: &mut Src) -> Result<(), String> {
        while !src.done() {
            self.step(src)?;
        }
        Ok(())
    }

    pub fn step(&mut self, src: &mut Src) -> Result<(), String> {
        let op = src.u8() as usize % OP_NAMES.len();
        self.stats.ops += 1;
        let types = [1u32, 2, 1, 2, 1, 2, 1, 2, 0, 3];
        let flags = [0u32, 1, 0, 1, 2];
        let max = self.max_payload;
        macro_rules! same_status {
            ($ra:expr, $rb:expr) => {{
                let (ia, ib) = (idx(&$ra), idx(&$rb));
                self.stats.outcomes[op][ia] += 1;
                if ia != ib {
                    return Err(format!(
                        "op #{} {}: status differs: a={:?} b={:?}",
                        self.stats.ops,
                        OP_NAMES[op],
                        $ra.as_ref().err(),
                        $rb.as_ref().err()
                    ));
                }
            }};
        }
        macro_rules! diverge {
            ($what:expr) => {
                return Err(format!("op #{} {}: {}", self.stats.ops, OP_NAMES[op], $what))
            };
        }
        match op {
            0 => {
                let (t, f) = (src.pick(&types), src.pick(&flags));
                let m = MATERIALS[src.u8() as usize % 4];
                let len = src.pick(&[32usize, 32, 32, 32, 32, 31, 33, 0]);
                let mat: Vec<u8> = m.iter().copied().cycle().take(len).collect();
                let (ra, rb) = (self.a.import_key(t, &mat, f), self.b.import_key(t, &mat, f));
                same_status!(ra, rb);
                if let (Ok(ia), Ok(ib)) = (ra, rb) {
                    if ia != ib {
                        diverge!("imported key IDs differ");
                    }
                    self.keys.push(Key { a: ia, b: ib, det: true });
                }
            }
            1 => {
                let (t, f) = (src.pick(&types), src.pick(&flags));
                let (ra, rb) = (self.a.generate(t, f), self.b.generate(t, f));
                same_status!(ra, rb);
                if let (Ok(ia), Ok(ib)) = (ra, rb) {
                    self.keys.push(Key { a: ia, b: ib, det: false });
                }
            }
            2 => {
                let k = self.key(src);
                let (ra, rb) = (self.a.destroy(&k.a), self.b.destroy(&k.b));
                same_status!(ra, rb);
            }
            3 => {
                let (w, t) = (self.key(src), self.key(src));
                let (ra, rb) = (self.a.wrap(&w.a, &t.a), self.b.wrap(&w.b, &t.b));
                same_status!(ra, rb);
                if let (Ok(ba), Ok(bb)) = (&ra, &rb) {
                    if (w.det && t.det && ba != bb) || ba.len() != bb.len() {
                        diverge!("wrapped blobs differ");
                    }
                    // det of the blob pair = det of its contents.
                    self.blobs.push((ba.clone(), bb.clone(), Key { det: w.det && t.det, ..w }));
                }
            }
            4 => {
                let (t, f) = (src.pick(&types), src.pick(&flags));
                let (mut ba, mut bb, kek) = match self.blobs.len() {
                    0 => (vec![0u8; 40], vec![0u8; 40], None),
                    n => {
                        let (a, b, k) = self.blobs[src.u8() as usize % n].clone();
                        (a, b, Some(k))
                    }
                };
                // Mostly the KEK that made the blob, so the success path runs.
                let (w, det) = match kek {
                    Some(k) if src.u8() % 4 != 0 => (k, k.det),
                    _ => (self.key(src), false),
                };
                match src.u8() % 6 {
                    0 => {
                        let i = src.u8() as usize % ba.len().max(1);
                        if i < ba.len() {
                            ba[i] ^= 1;
                            bb[i] ^= 1;
                        }
                    }
                    1 => {
                        ba.pop();
                        bb.pop();
                    }
                    _ => {}
                }
                let (ra, rb) = (self.a.unwrap(&w.a, t, &ba, f), self.b.unwrap(&w.b, t, &bb, f));
                same_status!(ra, rb);
                if let (Ok(ia), Ok(ib)) = (ra, rb) {
                    let det = det && w.det;
                    if det && ia != ib {
                        diverge!("unwrapped key IDs differ");
                    }
                    self.keys.push(Key { a: ia, b: ib, det });
                }
            }
            5 => {
                let k = self.key(src);
                let msg = src.bytes(max);
                let (ra, rb) = (self.a.hmac_sign(&k.a, &msg), self.b.hmac_sign(&k.b, &msg));
                same_status!(ra, rb);
                if let (Ok(ta), Ok(tb)) = (ra, rb) {
                    if k.det && ta != tb {
                        diverge!("HMAC tags differ");
                    }
                }
            }
            6 => {
                let k = self.key(src);
                let msg = src.bytes(max);
                // Each side verifies its own tag (which may be absent).
                let mut ta = self.a.hmac_sign(&k.a, &msg).map(|t| t.to_vec()).unwrap_or_else(|_| vec![0; 32]);
                let mut tb = self.b.hmac_sign(&k.b, &msg).map(|t| t.to_vec()).unwrap_or_else(|_| vec![0; 32]);
                match src.u8() % 4 {
                    0 => {
                        let i = src.u8() as usize % 32;
                        ta[i] ^= 0x40;
                        tb[i] ^= 0x40;
                    }
                    1 => {
                        let n = src.u8() as usize % 40;
                        ta.resize(n, 0);
                        tb.resize(n, 0);
                    }
                    _ => {}
                }
                let (ra, rb) = (self.a.hmac_verify(&k.a, &msg, &ta), self.b.hmac_verify(&k.b, &msg, &tb));
                same_status!(ra, rb);
            }
            7 => {
                let k = self.key(src);
                let nonce: Option<[u8; NONCE_LEN]> = match src.u8() % 4 {
                    0 => None,
                    1 => Some(ccb::KCV_NONCE),
                    _ => Some(std::array::from_fn(|_| src.u8())),
                };
                let (aad, pt) = (src.bytes(16), src.bytes(max));
                let (ra, rb) =
                    (self.a.seal(&k.a, nonce.as_ref(), &aad, &pt), self.b.seal(&k.b, nonce.as_ref(), &aad, &pt));
                same_status!(ra, rb);
                if let (Ok(sa), Ok(sb)) = (&ra, &rb) {
                    let det = k.det && nonce.is_some();
                    if (det && sa != sb) || sa.len() != sb.len() {
                        diverge!("sealed outputs differ");
                    }
                    self.sealed.push((sa.clone(), sb.clone(), aad, k));
                }
            }
            8 => {
                let (mut sa, mut sb, mut aad, sk) = match self.sealed.len() {
                    0 => (vec![], vec![], vec![], None),
                    n => {
                        let s = &self.sealed[src.u8() as usize % n];
                        (s.0.clone(), s.1.clone(), s.2.clone(), Some(s.3))
                    }
                };
                // Mostly the sealing key, so the success path runs.
                let k = match sk {
                    Some(k) if src.u8() % 4 != 0 => k,
                    _ => self.key(src),
                };
                match src.u8() % 8 {
                    0 if !sa.is_empty() => {
                        let i = src.u8() as usize % sa.len();
                        sa[i] ^= 0x01;
                        sb[i] ^= 0x01;
                    }
                    1 => {
                        let n = src.u8() as usize % 40;
                        sa.truncate(n);
                        sb.truncate(n);
                    }
                    2 if sa.len() >= NONCE_LEN && sa.len() == sb.len() => {
                        sa[..NONCE_LEN].copy_from_slice(&ccb::KCV_NONCE);
                        sb[..NONCE_LEN].copy_from_slice(&ccb::KCV_NONCE);
                    }
                    3 => aad.push(0),
                    _ => {}
                }
                let (ra, rb) = (self.a.open(&k.a, &aad, &sa), self.b.open(&k.b, &aad, &sb));
                same_status!(ra, rb);
                if let (Ok(pa), Ok(pb)) = (ra, rb) {
                    if pa != pb {
                        diverge!("opened plaintexts differ");
                    }
                }
            }
            9 => {
                let k = self.key(src);
                let (salt, info) = (src.bytes(16), src.bytes(16));
                let (t, f) = (src.pick(&types), src.pick(&flags));
                let (ra, rb) =
                    (self.a.hkdf_derive(&k.a, &salt, &info, t, f), self.b.hkdf_derive(&k.b, &salt, &info, t, f));
                same_status!(ra, rb);
                if let (Ok(ia), Ok(ib)) = (ra, rb) {
                    if k.det && ia != ib {
                        diverge!("derived key IDs differ");
                    }
                    self.keys.push(Key { a: ia, b: ib, det: k.det });
                }
            }
            _ => {
                // Seal on one side, open on the other: only meaningful for keys
                // both sides share.
                let k = self.key(src);
                if !k.det {
                    return Ok(());
                }
                let pt = src.bytes(max);
                let a_to_b = src.u8() % 2 == 0;
                let (from, to): (&mut dyn KeyStore, &mut dyn KeyStore) =
                    if a_to_b { (&mut *self.a, &mut *self.b) } else { (&mut *self.b, &mut *self.a) };
                let r = from.seal(&k.a, None, b"x", &pt).and_then(|s| to.open(&k.b, b"x", &s));
                self.stats.outcomes[op][idx(&r)] += 1;
                match r {
                    Ok(p) if p != pt => diverge!("cross-open returned a different plaintext"),
                    Err(s) if s != Status::NoSuchKey && s != Status::WrongKeyType => {
                        diverge!(format!("cross-open failed: {s:?}"))
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// Deterministic byte stream for seeded runs (xorshift64*).
pub fn seeded_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

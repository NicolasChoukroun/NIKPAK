//! "NAC" - nikpak's lossless PCM audio codec.
//!
//! Block based (like FLAC, but with its own bit-stream):
//!  * stereo decorrelation per block: L/R, L/S, S/R or M/S (reversible)
//!  * per channel: constant | verbatim | fixed polynomial predictor (order 0-4)
//!    | LPC predictor (order up to 32, quantised coefficients)
//!  * "wasted bits" (low bits that are always zero) are removed
//!  * residuals: partitioned Rice coding
//!
//! The decoder uses integer arithmetic only, so results are bit-exact on every
//! platform. The encoder uses floating point only to *choose* coefficients; the
//! chosen (integer) coefficients are written to the stream.

use crate::bits::{BitReader, BitWriter};

pub const BLOCK: usize = 4096;

const T_CONST: u64 = 0;
const T_VERB: u64 = 1;
const T_FIXED: u64 = 2;
const T_LPC: u64 = 3;

const MAX_PO: u32 = 8;
const MAX_ORDER: usize = 32;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

#[inline]
fn zz(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
#[inline]
fn unzz(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}
#[inline]
fn part_bound(len: usize, p: u32, i: usize) -> usize {
    ((i as u64 * len as u64) >> p) as usize
}

/// Best Rice parameter for a partition (approximate, from the sum).
fn best_k(sum: u64, count: u64) -> (u32, u64) {
    if count == 0 {
        return (0, 0);
    }
    let mean = (sum + count / 2) / count;
    let k0 = if mean == 0 { 0 } else { 63 - mean.leading_zeros() };
    let mut best = (0u32, u64::MAX);
    let k0 = k0.min(31);
    for k in k0.saturating_sub(1)..=(k0 + 1).min(31) {
        let cost = count * (k as u64 + 1) + (sum >> k);
        if cost < best.1 {
            best = (k, cost);
        }
    }
    best
}

struct ResidualPlan {
    cost: u64,
    po: u32,
    ks: Vec<u32>,
}

fn plan_residual(res: &[i64]) -> ResidualPlan {
    let len = res.len();
    let mut prefix = Vec::with_capacity(len + 1);
    prefix.push(0u64);
    let mut acc = 0u64;
    for &r in res {
        acc = acc.wrapping_add(zz(r));
        prefix.push(acc);
    }
    let mut po_max = 0;
    while po_max < MAX_PO && (len >> (po_max + 1)) >= 16 {
        po_max += 1;
    }
    let mut best: Option<ResidualPlan> = None;
    for po in 0..=po_max {
        let parts = 1usize << po;
        let mut cost = 4u64;
        let mut ks = Vec::with_capacity(parts);
        for i in 0..parts {
            let a = part_bound(len, po, i);
            let b = part_bound(len, po, i + 1);
            let sum = prefix[b].wrapping_sub(prefix[a]);
            let (k, c) = best_k(sum, (b - a) as u64);
            cost += 5 + c;
            ks.push(k);
        }
        if best.as_ref().map_or(true, |bp| cost < bp.cost) {
            best = Some(ResidualPlan { cost, po, ks });
        }
    }
    best.unwrap()
}

fn write_residual(bw: &mut BitWriter, res: &[i64], plan: &ResidualPlan) {
    bw.put(plan.po as u64, 4);
    let len = res.len();
    for (i, &k) in plan.ks.iter().enumerate() {
        bw.put(k as u64, 5);
        let a = part_bound(len, plan.po, i);
        let b = part_bound(len, plan.po, i + 1);
        for &r in &res[a..b] {
            let u = zz(r);
            bw.unary(u >> k);
            bw.put(u & ((1u64 << k) - 1), k);
        }
    }
}

fn read_residual(br: &mut BitReader, len: usize) -> Result<Vec<i64>, String> {
    let po = br.get(4)? as u32;
    if po > MAX_PO {
        return Err("corrupt audio block (partition order)".into());
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..(1usize << po) {
        let k = br.get(5)? as u32;
        let a = part_bound(len, po, i);
        let b = part_bound(len, po, i + 1);
        for _ in a..b {
            let q = br.unary()?;
            let low = br.get(k)?;
            let u = (q.wrapping_shl(k)) | low;
            out.push(unzz(u));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// predictors
// ---------------------------------------------------------------------------

fn fixed_residual(x: &[i64], order: usize) -> Vec<i64> {
    let n = x.len();
    let mut r = Vec::with_capacity(n - order);
    for i in order..n {
        let p = match order {
            0 => 0,
            1 => x[i - 1],
            2 => 2 * x[i - 1] - x[i - 2],
            3 => 3 * x[i - 1] - 3 * x[i - 2] + x[i - 3],
            _ => 4 * x[i - 1] - 6 * x[i - 2] + 4 * x[i - 3] - x[i - 4],
        };
        r.push(x[i] - p);
    }
    r
}

fn fixed_restore(res: &[i64], x: &mut Vec<i64>, order: usize) {
    for (j, &r) in res.iter().enumerate() {
        let i = order + j;
        let p = match order {
            0 => 0,
            1 => x[i - 1],
            2 => x[i - 1].wrapping_mul(2).wrapping_sub(x[i - 2]),
            3 => x[i - 1].wrapping_mul(3).wrapping_sub(x[i - 2].wrapping_mul(3)).wrapping_add(x[i - 3]),
            _ => x[i - 1]
                .wrapping_mul(4)
                .wrapping_sub(x[i - 2].wrapping_mul(6))
                .wrapping_add(x[i - 3].wrapping_mul(4))
                .wrapping_sub(x[i - 4]),
        };
        x.push(r.wrapping_add(p));
    }
}

fn lpc_residual(x: &[i64], q: &[i64], shift: u32) -> Vec<i64> {
    let n = x.len();
    let order = q.len();
    let mut r = Vec::with_capacity(n - order);
    for i in order..n {
        let mut s = 0i64;
        for (j, &c) in q.iter().enumerate() {
            s += c * x[i - 1 - j];
        }
        r.push(x[i] - (s >> shift));
    }
    r
}

fn lpc_restore(res: &[i64], x: &mut Vec<i64>, q: &[i64], shift: u32) {
    let order = q.len();
    for (j, &r) in res.iter().enumerate() {
        let i = order + j;
        let mut s = 0i64;
        for (t, &c) in q.iter().enumerate() {
            s = s.wrapping_add(c.wrapping_mul(x[i - 1 - t]));
        }
        x.push(r.wrapping_add(s >> shift));
    }
}

/// Windowed autocorrelation + Levinson-Durbin. Returns coefficient sets for
/// orders 1..=max (predict x[i] = sum a[j] * x[i-1-j]).
fn lpc_analysis(x: &[i64], max_order: usize) -> Vec<Vec<f64>> {
    let n = x.len();
    let mut w: Vec<f64> = x.iter().map(|&v| v as f64).collect();
    // Tukey(0.5) window
    let taper = n / 4;
    for i in 0..taper {
        let f = 0.5 - 0.5 * (std::f64::consts::PI * i as f64 / taper as f64).cos();
        w[i] *= f;
        w[n - 1 - i] *= f;
    }
    let mut r = vec![0.0f64; max_order + 1];
    for lag in 0..=max_order {
        let mut s = 0.0;
        for i in lag..n {
            s += w[i] * w[i - lag];
        }
        r[lag] = s;
    }
    if r[0] <= 0.0 {
        return Vec::new();
    }
    r[0] *= 1.0 + 1e-9;
    let mut a = vec![0.0f64; max_order + 1];
    let mut err = r[0];
    let mut out = Vec::new();
    for i in 1..=max_order {
        let mut acc = r[i];
        for j in 1..i {
            acc -= a[j] * r[i - j];
        }
        let k = acc / err;
        let mut na = a.clone();
        na[i] = k;
        for j in 1..i {
            na[j] = a[j] - k * a[i - j];
        }
        a = na;
        err *= 1.0 - k * k;
        out.push(a[1..=i].to_vec());
        if err <= 1e-12 * r[0] {
            break;
        }
    }
    out
}

fn quantize(c: &[f64], precision: u32) -> Option<(Vec<i64>, u32)> {
    let cmax = c.iter().fold(0.0f64, |m, &v| v.abs().max(m));
    if !(cmax > 0.0) || !cmax.is_finite() {
        return None;
    }
    let log2 = cmax.log2().floor() as i32 + 1;
    let shift = (precision as i32 - 1 - log2).clamp(0, 20) as u32;
    let lim = (1i64 << (precision - 1)) - 1;
    let scale = (1u64 << shift) as f64;
    let mut err = 0.0f64;
    let mut q = Vec::with_capacity(c.len());
    for &v in c {
        let t = v * scale + err;
        let qi = (t.round() as i64).clamp(-lim - 1, lim);
        err = t - qi as f64;
        q.push(qi);
    }
    Some((q, shift))
}

// ---------------------------------------------------------------------------
// sub-frame (one channel of one block)
// ---------------------------------------------------------------------------

enum Choice {
    Verbatim,
    Fixed { order: usize, res: Vec<i64>, plan: ResidualPlan },
    Lpc { q: Vec<i64>, shift: u32, prec: u32, res: Vec<i64>, plan: ResidualPlan },
}

fn lpc_orders(level: u32) -> &'static [usize] {
    match level {
        0 => &[8, 16],
        1 => &[4, 8, 12, 16, 24, 32],
        _ => &[2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32],
    }
}

fn encode_sub(bw: &mut BitWriter, x: &[i64], bps: u32, level: u32, force_verbatim: bool) {
    let n = x.len();
    if !force_verbatim && x.iter().all(|&v| v == x[0]) {
        bw.put(T_CONST, 2);
        bw.put_signed(x[0], bps);
        return;
    }
    let or = x.iter().fold(0i64, |a, &v| a | v);
    let w = if or == 0 { 0 } else { (or.trailing_zeros()).min(bps.saturating_sub(1)) };
    let shifted: Vec<i64>;
    let xs: &[i64] = if w > 0 {
        shifted = x.iter().map(|&v| v >> w).collect();
        &shifted
    } else {
        x
    };
    let b = bps - w;

    let mut best = Choice::Verbatim;
    let mut best_cost = 2 + 5 + n as u64 * b as u64;

    if !force_verbatim {
        // fixed predictors
        for order in 0..=4usize.min(n.saturating_sub(1)) {
            let res = fixed_residual(xs, order);
            let plan = plan_residual(&res);
            let cost = 2 + 5 + 3 + order as u64 * b as u64 + plan.cost;
            if cost < best_cost {
                best_cost = cost;
                best = Choice::Fixed { order, res, plan };
            }
        }
        // LPC
        if n >= 64 {
            let prec: u32 = if b <= 9 { 12 } else if b <= 17 { 14 } else { 15 };
            let orders = lpc_orders(level);
            let max_order = (*orders.last().unwrap()).min(MAX_ORDER).min(n / 2);
            let sets = lpc_analysis(xs, max_order);
            for &order in orders {
                if order > sets.len() {
                    continue;
                }
                let Some((q, shift)) = quantize(&sets[order - 1], prec) else { continue };
                let res = lpc_residual(xs, &q, shift);
                let plan = plan_residual(&res);
                let cost = 2 + 5 + 5 + 4 + 5 + order as u64 * (prec as u64 + b as u64) + plan.cost;
                if cost < best_cost {
                    best_cost = cost;
                    best = Choice::Lpc { q, shift, prec, res, plan };
                }
            }
        }
    }

    match best {
        Choice::Verbatim => {
            bw.put(T_VERB, 2);
            bw.put(w as u64, 5);
            for &v in xs {
                bw.put_signed(v, b);
            }
        }
        Choice::Fixed { order, res, plan } => {
            bw.put(T_FIXED, 2);
            bw.put(w as u64, 5);
            bw.put(order as u64, 3);
            for &v in &xs[..order] {
                bw.put_signed(v, b);
            }
            write_residual(bw, &res, &plan);
        }
        Choice::Lpc { q, shift, prec, res, plan } => {
            bw.put(T_LPC, 2);
            bw.put(w as u64, 5);
            bw.put((q.len() - 1) as u64, 5);
            bw.put((prec - 1) as u64, 4);
            bw.put(shift as u64, 5);
            for &c in &q {
                bw.put_signed(c, prec);
            }
            for &v in &xs[..q.len()] {
                bw.put_signed(v, b);
            }
            write_residual(bw, &res, &plan);
        }
    }
}

fn decode_sub(br: &mut BitReader, n: usize, bps: u32) -> Result<Vec<i64>, String> {
    let t = br.get(2)?;
    if t == T_CONST {
        let v = br.get_signed(bps)?;
        return Ok(vec![v; n]);
    }
    let w = br.get(5)? as u32;
    if w >= bps {
        return Err("corrupt audio block (wasted bits)".into());
    }
    let b = bps - w;
    let mut x: Vec<i64> = Vec::with_capacity(n);
    match t {
        T_VERB => {
            for _ in 0..n {
                x.push(br.get_signed(b)?);
            }
        }
        T_FIXED => {
            let order = br.get(3)? as usize;
            if order > 4 || order >= n {
                return Err("corrupt audio block (fixed order)".into());
            }
            for _ in 0..order {
                x.push(br.get_signed(b)?);
            }
            let res = read_residual(br, n - order)?;
            fixed_restore(&res, &mut x, order);
        }
        _ => {
            let order = br.get(5)? as usize + 1;
            let prec = br.get(4)? as u32 + 1;
            let shift = br.get(5)? as u32;
            if order >= n || prec < 2 || shift > 40 {
                return Err("corrupt audio block (lpc header)".into());
            }
            let mut q = Vec::with_capacity(order);
            for _ in 0..order {
                q.push(br.get_signed(prec)?);
            }
            for _ in 0..order {
                x.push(br.get_signed(b)?);
            }
            let res = read_residual(br, n - order)?;
            lpc_restore(&res, &mut x, &q, shift);
        }
    }
    if w > 0 {
        for v in x.iter_mut() {
            *v = v.wrapping_shl(w);
        }
    }
    Ok(x)
}

// ---------------------------------------------------------------------------
// block level
// ---------------------------------------------------------------------------

fn order2_cost(x: &[i64]) -> u64 {
    let mut s = 0u64;
    for i in 2..x.len() {
        s += (x[i] - 2 * x[i - 1] + x[i - 2]).unsigned_abs();
    }
    s
}

/// Encode one block. `chans[c]` holds the samples of channel c.
pub fn encode_block(chans: &[Vec<i64>], bits: u32, level: u32, force_verbatim: bool) -> Vec<u8> {
    let mut bw = BitWriter::new();
    if chans.len() == 2 {
        let l = &chans[0];
        let r = &chans[1];
        let s: Vec<i64> = l.iter().zip(r).map(|(a, b)| a - b).collect();
        let m: Vec<i64> = l.iter().zip(r).map(|(a, b)| (a + b) >> 1).collect();
        let (el, er, em, es) = (order2_cost(l), order2_cost(r), order2_cost(&m), order2_cost(&s));
        let cands = [(el + er, 0u64), (el + es, 1), (es + er, 2), (em + es, 3)];
        let mode = if force_verbatim { 0 } else { cands.iter().min_by_key(|c| c.0).unwrap().1 };
        bw.put(mode, 2);
        let b1 = bits + 1;
        match mode {
            0 => {
                encode_sub(&mut bw, l, bits, level, force_verbatim);
                encode_sub(&mut bw, r, bits, level, force_verbatim);
            }
            1 => {
                encode_sub(&mut bw, l, bits, level, force_verbatim);
                encode_sub(&mut bw, &s, b1, level, force_verbatim);
            }
            2 => {
                encode_sub(&mut bw, &s, b1, level, force_verbatim);
                encode_sub(&mut bw, r, bits, level, force_verbatim);
            }
            _ => {
                encode_sub(&mut bw, &m, bits, level, force_verbatim);
                encode_sub(&mut bw, &s, b1, level, force_verbatim);
            }
        }
    } else {
        for ch in chans {
            encode_sub(&mut bw, ch, bits, level, force_verbatim);
        }
    }
    bw.finish()
}

pub fn decode_block(data: &[u8], channels: usize, bits: u32, n: usize) -> Result<Vec<Vec<i64>>, String> {
    let mut br = BitReader::new(data);
    if channels == 2 {
        let mode = br.get(2)?;
        let b1 = bits + 1;
        let (b0, b_1) = match mode {
            0 => (bits, bits),
            1 => (bits, b1),
            2 => (b1, bits),
            _ => (bits, b1),
        };
        let a = decode_sub(&mut br, n, b0)?;
        let c = decode_sub(&mut br, n, b_1)?;
        let (l, r): (Vec<i64>, Vec<i64>) = match mode {
            0 => (a, c),
            1 => {
                let r = a.iter().zip(&c).map(|(l, s)| l.wrapping_sub(*s)).collect();
                (a, r)
            }
            2 => {
                let l = a.iter().zip(&c).map(|(s, r)| r.wrapping_add(*s)).collect();
                (l, c)
            }
            _ => {
                let mut l = Vec::with_capacity(n);
                let mut r = Vec::with_capacity(n);
                for (m, s) in a.iter().zip(&c) {
                    let sum = m.wrapping_shl(1) | (s & 1);
                    l.push(sum.wrapping_add(*s) >> 1);
                    r.push(sum.wrapping_sub(*s) >> 1);
                }
                (l, r)
            }
        };
        Ok(vec![l, r])
    } else {
        let mut out = Vec::with_capacity(channels);
        for _ in 0..channels {
            out.push(decode_sub(&mut br, n, bits)?);
        }
        Ok(out)
    }
}

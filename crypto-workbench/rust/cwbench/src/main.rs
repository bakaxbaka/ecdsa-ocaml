// cwbench — release-mode self-tests + benchmarks for the crypto workbench.
// Uses well-tested audited crates (RustCrypto sha2/hmac/aes, k256, num-bigint).
// Subcommands:
//   selftest         — vector + cross-language value checks; prints RESULT lines
//   bench <secs>     — single-threaded benchmarks; prints RESULT lines
//   bench-par <n>    — rayon-parallel sha256 throughput with n threads
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn result(k: &str, v: &str) {
    println!("RESULT {} {}", k, v);
}

fn selftest() -> i32 {
    let mut ok = true;
    // SHA-256 NIST vectors
    let h1 = hexs(&Sha256::digest(b"abc"));
    ok &= h1 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    result("sha256_abc", &h1);
    let h2 = hexs(&Sha256::digest(b""));
    ok &= h2 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    result("sha256_empty", &h2);
    let h3 = hexs(&Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    ok &= h3 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    result("sha256_448bit", &h3);
    // HMAC-SHA256 RFC4231 case 1
    let key = [0x0bu8; 20];
    let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(b"Hi There");
    let hm = hexs(&mac.finalize().into_bytes());
    ok &= hm == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    result("hmac_rfc4231_1", &hm);
    // double-sha256 (Bitcoin style) of "hello"
    let d = Sha256::digest(Sha256::digest(b"hello"));
    result("dsha256_hello", &hexs(&d));
    // AES-128 FIPS-197 vector
    let keyb = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let key = GenericArray::from_slice(&keyb);
    let blkb = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let mut blk = GenericArray::clone_from_slice(&blkb);
    aes::Aes128::new(key).encrypt_block(&mut blk);
    let ct = hexs(&blk);
    ok &= ct == "69c4e0d86a7b0430d8cdb78070b4c55a";
    result("aes128_fips197", &ct);
    // num-bigint modexp/inverse/gcd values for cross-language compare
    let p = BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16).unwrap();
    let g = BigUint::from(7u32);
    let e = BigUint::parse_bytes(b"deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe", 16).unwrap();
    let m = g.modpow(&e, &p);
    result("modexp_7_e_p", &m.to_str_radix(16));
    let a = BigUint::parse_bytes(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16).unwrap();
    let inv = a.clone().modinv(&p).unwrap();
    result("modinv_a_p", &inv.to_str_radix(16));
    let x = BigUint::parse_bytes(b"5f4dcc3b5aa765d61d8327deb882cf99aaaaaaaaaaaaaaaa", 16).unwrap();
    let y = BigUint::parse_bytes(b"7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70891", 16).unwrap();
    result("gcd_x_y", &x.gcd(&y).to_str_radix(16));
    result("mulmod_x_y_p", &(x * y.clone() % &p).to_str_radix(16));
    // k256 ECDSA verify of the BIP143 P2WPKH vector
    let pk = hex::decode("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357").unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk).unwrap();
    let r = "3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a";
    let s = "573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee";
    let sig = Signature::from_scalars(
        GenericArray::clone_from_slice(&hex::decode(r).unwrap()),
        GenericArray::clone_from_slice(&hex::decode(s).unwrap()),
    ).unwrap();
    let z = hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670").unwrap();
    let v = vk.verify_prehash(&z, &sig).is_ok();
    ok &= v;
    result("k256_bip143_verify", if v { "OK" } else { "FAIL" });
    // secp256k1 n*G must be identity (via k256 arithmetic)
    use k256::{ProjectivePoint, Scalar};
    use k256::elliptic_curve::group::{Group, GroupEncoding};
    use k256::elliptic_curve::PrimeField;
    let n_minus_1 = Scalar::from_repr(
        GenericArray::clone_from_slice(&hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140").unwrap())
    ).unwrap();
    let g = ProjectivePoint::generator();
    let should_be_neg_g = g * n_minus_1;
    let neg_g = -g;
    ok &= should_be_neg_g == neg_g;
    result("k256_order_check", if should_be_neg_g == neg_g { "OK" } else { "FAIL" });
    // serialization roundtrip (serde+bincode)
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Tx { version: i32, locktime: u32, vin: Vec<(String, u32, u32)>, vout: Vec<(i64, String)> }
    let t = Tx { version: 2, locktime: 0,
                 vin: vec![("aa".repeat(32), 0, 0xfffffffd)],
                 vout: vec![(123456789, "76a914".to_string())] };
    let bytes = bincode::serialize(&t).unwrap();
    let t2: Tx = bincode::deserialize(&bytes).unwrap();
    ok &= t == t2;
    let br = if t == t2 { format!("OK len={}", bytes.len()) } else { "FAIL".to_string() };
    result("bincode_roundtrip", &br);
    result("selftest", if ok { "ALL_PASS" } else { "FAILURES" });
    if ok { 0 } else { 1 }
}

fn bench(secs_each: f64) -> i32 {
    // 1) bigint: 256-bit modmul & modexp & modinv via num-bigint
    let p = BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16).unwrap();
    let a = BigUint::parse_bytes(b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16).unwrap();
    let b = BigUint::parse_bytes(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16).unwrap();
    let e = BigUint::from(65537u32);
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(a.clone() * b.clone() % p.clone());
        n += 1;
    }
    result("bigint_modmul_ops_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(a.modpow(&e, &p));
        n += 1;
    }
    result("bigint_modexp_e65537_ops_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(b.modinv(&p));
        n += 1;
    }
    result("bigint_modinv_ops_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(a.gcd(&b));
        n += 1;
    }
    result("bigint_gcd_ops_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    // 2) sha256 throughput
    let chunk = vec![0x5au8; 4096];
    let t0 = Instant::now(); let mut bytes = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(Sha256::digest(&chunk));
        bytes += 4096;
    }
    result("sha256_MB_per_s", &format!("{:.1}", bytes as f64 / secs_each / 1e6));
    // 3) aes-128 throughput
    let key = GenericArray::from_slice(&[0u8; 16]);
    let cipher = aes::Aes128::new(key);
    let t0 = Instant::now(); let mut blocks = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let mut blk = GenericArray::clone_from_slice(&[0u8; 16]);
        cipher.encrypt_block(&mut blk);
        blocks += 1;
        std::hint::black_box(&blk);
    }
    result("aes128_MB_per_s", &format!("{:.1}", blocks as f64 * 16.0 / secs_each / 1e6));
    // 4) k256 EC: scalar mult (verify) + sign
    let pk = hex::decode("02507a40492642239fc7eae74bc1f1beb15a6079ea3702cfdaeec2268bb00bcbd0").unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk).unwrap();
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()).unwrap();
    let z = [0x42u8; 32];
    let sig: Signature = {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        sk.sign_prehash(&z).unwrap()
    };
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let _ = std::hint::black_box(vk.verify_prehash(&z, &sig));
        n += 1;
    }
    result("k256_ecdsa_verify_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let s2: Signature = sk.sign_prehash(&z).unwrap();
        std::hint::black_box(s2);
        n += 1;
    }
    result("k256_ecdsa_sign_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    use k256::{ProjectivePoint, Scalar};
    use k256::elliptic_curve::group::{Group, GroupEncoding};
    use k256::elliptic_curve::PrimeField;
    let sc = Scalar::from_repr(GenericArray::clone_from_slice(&z)).unwrap();
    let t0 = Instant::now(); let mut n = 0u64;
    while t0.elapsed().as_secs_f64() < secs_each {
        let pt = ProjectivePoint::generator() * sc;
        std::hint::black_box(pt.to_bytes());
        n += 1;
    }
    result("k256_scalarmult_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    // 5) serialization: bincode of a 1-in/2-out struct
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Tx { version: i32, locktime: u32, vin: Vec<(String, u32, u32)>, vout: Vec<(i64, String)> }
    let t = Tx { version: 2, locktime: 0,
                 vin: vec![("aa".repeat(32), 0, 0xfffffffd)],
                 vout: vec![(123456789, "76a914bb".to_string()), (987654321, "0014cc".to_string())] };
    let t0 = Instant::now(); let mut n = 0u64; let mut acc = 0usize;
    while t0.elapsed().as_secs_f64() < secs_each {
        let bytes = bincode::serialize(&t).unwrap();
        let t2: Tx = bincode::deserialize(&bytes).unwrap();
        acc += t2.vin.len();
        std::hint::black_box(bytes);
        n += 1;
    }
    result("serde_bincode_roundtrip_per_s", &format!("{}", (n as f64 / secs_each) as u64));
    0
}

fn bench_par(threads: usize, secs: f64) -> i32 {
    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().ok();
    let chunk = vec![0x5au8; 4096];
    let work: Vec<usize> = (0..200_000).collect();
    use rayon::prelude::*;
    let t0 = Instant::now();
    let mut bytes = 0u64;
    while t0.elapsed().as_secs_f64() < secs {
        let n = work.par_iter().map(|_| { let h = Sha256::digest(&chunk); std::hint::black_box(h[0]) }).count();
        bytes += (n * 4096) as u64;
        if t0.elapsed().as_secs_f64() > secs { break; }
    }
    let dt = t0.elapsed().as_secs_f64();
    result(&format!("sha256_par{}_MB_per_s", threads), &format!("{:.1}", bytes as f64 / dt / 1e6));
    0
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("selftest");
    let code = match cmd {
        "selftest" => selftest(),
        "bench" => bench(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0)),
        "bench-par" => bench_par(
            args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2),
            args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2.0)),
        _ => { eprintln!("unknown cmd"); 2 }
    };
    std::process::ExitCode::from(code as u8)
}

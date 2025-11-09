#!/usr/bin/env python3
import argparse
import os
import sys
import time
import math
import struct
import tracemalloc
import tempfile
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

# Dependencies:
#   pip install cryptography pandas
#
# WARNING:
#   The --force-direct-rsa-chunked mode below demonstrates "RSA on big files"
#   by chunking the plaintext into OAEP-sized blocks and encrypting each with RSA.
#   This is educational ONLY. It is dramatically slower and much larger than hybrid
#   RSA+AES, and offers no security advantage. Use hybrid in practice.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

try:
    import pandas as pd
except ImportError:
    pd = None

def now() -> float:
    return time.perf_counter()

@dataclass
class BenchRow:
    algorithm: str
    operation: str
    file: str
    size_bytes: int
    key_bits: int
    duration_s: float
    throughput_MBps: Optional[float]
    peak_mem_kB: int
    notes: str = ""

AES_NONCE_LEN = 12
AES_TAG_LEN = 16
CHUNK_SIZE = 64 * 1024  # streaming size

def generate_sample_files(out_dir: Path, sizes: List[int]) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for sz in sizes:
        p = out_dir / f"sample_{sz}B.bin"
        if not p.exists() or p.stat().st_size != sz:
            with open(p, "wb") as f:
                f.write(os.urandom(sz))
        out.append(p)
    return out

def aes_keygen(bits: int = 256) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES bits must be 128, 192, or 256")
    return os.urandom(bits // 8)

def aes_gcm_encrypt_file(in_path: Path, out_path: Path, key: bytes) -> None:
    nonce = os.urandom(AES_NONCE_LEN)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(nonce)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
        encryptor.finalize()
        fout.write(encryptor.tag)

def aes_gcm_decrypt_file(in_path: Path, out_path: Path, key: bytes) -> None:
    with open(in_path, "rb") as fin:
        data = fin.read()
    nonce = data[:AES_NONCE_LEN]
    tag = data[-AES_TAG_LEN:]
    ct = data[AES_NONCE_LEN:-AES_TAG_LEN]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    with open(out_path, "wb") as fout:
        fout.write(pt)

def rsa_keygen(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def rsa_plaintext_limit_bytes(key_bits: int, hash_alg=hashes.SHA256()) -> int:
    k = key_bits // 8
    h_len = hash_alg.digest_size
    return k - 2*h_len - 2

def rsa_oaep_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Chunked RSA file mode (educational only) ---
# Ciphertext layout:
#   [4-byte big-endian chunk_count]
#   repeated:
#     [4-byte big-endian ct_len][ct_bytes]
def rsa_chunked_encrypt_file(in_path: Path, out_path: Path, rsa_pub, key_bits: int):
    limit = rsa_plaintext_limit_bytes(key_bits, hashes.SHA256())
    if limit <= 0:
        raise ValueError("OAEP plaintext limit computed as <= 0")
    chunk_count = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(struct.pack(">I", 0))  # placeholder for chunk_count
        while True:
            pt = fin.read(limit)
            if not pt:
                break
            ct = rsa_oaep_encrypt(rsa_pub, pt)
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            chunk_count += 1
        # go back and fill in chunk count
        fout.seek(0)
        fout.write(struct.pack(">I", chunk_count))

def rsa_chunked_decrypt_file(in_path: Path, out_path: Path, rsa_priv):
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        header = fin.read(4)
        if len(header) != 4:
            raise ValueError("Invalid chunked RSA header")
        chunk_count = struct.unpack(">I", header)[0]
        for _ in range(chunk_count):
            len_bytes = fin.read(4)
            if len(len_bytes) != 4:
                raise ValueError("Truncated chunk length")
            ct_len = struct.unpack(">I", len_bytes)[0]
            ct = fin.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError("Truncated ciphertext chunk")
            pt = rsa_oaep_decrypt(rsa_priv, ct)
            fout.write(pt)

def hybrid_encrypt_file(in_path: Path, out_path: Path, rsa_pub, aes_bits: int = 256):
    aes_key = aes_keygen(aes_bits)
    wrapped_key = rsa_oaep_encrypt(rsa_pub, aes_key)
    with tempfile.NamedTemporaryFile(delete=False) as tmp_ct:
        tmp_ct_path = Path(tmp_ct.name)
    try:
        aes_gcm_encrypt_file(in_path, tmp_ct_path, aes_key)
        wrapped_len = len(wrapped_key)
        if wrapped_len >= 65535:
            raise ValueError("Wrapped key too large for 2-byte prefix.")
        with open(out_path, "wb") as fout, open(tmp_ct_path, "rb") as fin_ct:
            fout.write(wrapped_len.to_bytes(2, "big"))
            fout.write(wrapped_key)
            fout.write(fin_ct.read())
    finally:
        if tmp_ct_path.exists():
            tmp_ct_path.unlink(missing_ok=True)

def hybrid_decrypt_file(in_path: Path, out_path: Path, rsa_priv):
    with open(in_path, "rb") as fin:
        data = fin.read()
    wrapped_len = int.from_bytes(data[:2], "big")
    wrapped_key = data[2:2+wrapped_len]
    aes_blob = data[2+wrapped_len:]
    aes_key = rsa_oaep_decrypt(rsa_priv, wrapped_key)
    nonce = aes_blob[:AES_NONCE_LEN]
    tag = aes_blob[-AES_TAG_LEN:]
    ct = aes_blob[AES_NONCE_LEN:-AES_TAG_LEN]
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag)).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    with open(out_path, "wb") as fout:
        fout.write(pt)

def measure(func, *args, **kwargs) -> Tuple[float, int, any]:
    tracemalloc.start()
    t0 = now()
    result = func(*args, **kwargs)
    dur = now() - t0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return dur, math.ceil(peak / 1024), result

def measure_repeated(func, repeats: int, *args, **kwargs) -> Tuple[float, int, any]:
    """
    Run `func` `repeats` times; return (avg_duration, max_peak_kB, last_result).
    """
    durations = []
    max_peak = 0
    last_result = None
    for _ in range(repeats):
        dur, peak, res = measure(func, *args, **kwargs)
        durations.append(dur)
        if peak > max_peak:
            max_peak = peak
        last_result = res
    avg_dur = sum(durations) / len(durations) if durations else 0.0
    return avg_dur, max_peak, last_result

def verify_equal(a: Path, b: Path) -> bool:
    CH = 64 * 1024
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x = fa.read(CH)
            y = fb.read(CH)
            if not x and not y:
                return True
            if x != y:
                return False

@dataclass
class Config:
    out_dir: Path
    sizes: List[int]
    aes_bits: int
    rsa_bits: int
    include_keygen: bool
    force_direct_rsa_chunked: bool
    repeats: int = 3

def run(cfg: Config) -> List[BenchRow]:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    samples = generate_sample_files(cfg.out_dir / "samples", cfg.sizes)
    work = cfg.out_dir / "work"
    work.mkdir(exist_ok=True)

    rows: List[BenchRow] = []

    if cfg.include_keygen:
        dur, peak, priv = measure_repeated(rsa_keygen, cfg.repeats, cfg.rsa_bits)
        rows.append(BenchRow(
            f"RSA-{cfg.rsa_bits}", "keygen", "-", 0, cfg.rsa_bits,
            dur, None, peak, notes=f"{cfg.repeats}-run avg"
        ))
    else:
        priv = rsa_keygen(cfg.rsa_bits)
    pub = priv.public_key()

    aes_key = aes_keygen(cfg.aes_bits)

    # AES streaming
    for p in samples:
        ct = work / (p.stem + ".aesgcm.bin")
        pt2 = work / (p.stem + ".aesgcm.dec")

        dur, peak, _ = measure_repeated(aes_gcm_encrypt_file, cfg.repeats, p, ct, aes_key)
        thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
        rows.append(BenchRow(
            f"AES-GCM-{cfg.aes_bits}", "encrypt", p.name, p.stat().st_size,
            cfg.aes_bits, dur, thr, peak, notes=f"{cfg.repeats}-run avg"
        ))

        dur, peak, _ = measure_repeated(aes_gcm_decrypt_file, cfg.repeats, ct, pt2, aes_key)
        thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
        ok = verify_equal(p, pt2)
        rows.append(BenchRow(
            f"AES-GCM-{cfg.aes_bits}", "decrypt", p.name, p.stat().st_size,
            cfg.aes_bits, dur, thr, peak, notes=f"verified={ok}; {cfg.repeats}-run avg"
        ))

    print("AES done")
    # Hybrid RSA+AES
    for p in samples:
        ct = work / (p.stem + f".hybrid_rsa{cfg.rsa_bits}.bin")
        pt2 = work / (p.stem + f".hybrid_rsa{cfg.rsa_bits}.dec")

        dur, peak, _ = measure_repeated(hybrid_encrypt_file, cfg.repeats, p, ct, pub, cfg.aes_bits)
        thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
        rows.append(BenchRow(
            f"Hybrid(RSA{cfg.rsa_bits}+AES{cfg.aes_bits})", "encrypt", p.name, p.stat().st_size,
            cfg.rsa_bits, dur, thr, peak, notes=f"RSA wraps AES key; {cfg.repeats}-run avg"
        ))

        dur, peak, _ = measure_repeated(hybrid_decrypt_file, cfg.repeats, ct, pt2, priv)
        thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
        ok = verify_equal(p, pt2)
        rows.append(BenchRow(
            f"Hybrid(RSA{cfg.rsa_bits}+AES{cfg.aes_bits})", "decrypt", p.name, p.stat().st_size,
            cfg.rsa_bits, dur, thr, peak, notes=f"verified={ok}; {cfg.repeats}-run avg"
        ))

    # Direct RSA chunked (educational)
    if cfg.force_direct_rsa_chunked:
        for p in samples:
            print("RSA chunked on", p)
            ct = work / (p.stem + f".rsa{cfg.rsa_bits}.chunked.bin")
            pt2 = work / (p.stem + f".rsa{cfg.rsa_bits}.chunked.dec")

            dur, peak, _ = measure_repeated(rsa_chunked_encrypt_file, cfg.repeats, p, ct, pub, cfg.rsa_bits)
            thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
            rows.append(BenchRow(
                f"RSA-OAEP-{cfg.rsa_bits}-chunked", "encrypt", p.name, p.stat().st_size,
                cfg.rsa_bits, dur, thr, peak, notes=f"inefficient; educational only; {cfg.repeats}-run avg"
            ))

            dur, peak, _ = measure_repeated(rsa_chunked_decrypt_file, cfg.repeats, ct, pt2, priv)
            thr = (p.stat().st_size / (1024*1024)) / dur if dur > 0 else None
            ok = verify_equal(p, pt2)
            rows.append(BenchRow(
                f"RSA-OAEP-{cfg.rsa_bits}-chunked", "decrypt", p.name, p.stat().st_size,
                cfg.rsa_bits, dur, thr, peak, notes=f"verified={ok}; inefficient; {cfg.repeats}-run avg"
            ))

    return rows

def write_results(rows: List[BenchRow], out_csv: Path):
    import csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for r in rows:
            writer.writerow(asdict(r))
    if pd is not None:
        try:
            df = pd.DataFrame([asdict(r) for r in rows])
            df.to_excel(out_csv.with_suffix(".xlsx"), index=False)
        except Exception:
            pass

def parse_sizes(s: str) -> List[int]:
    try:
        return [int(x.strip()) for x in s.split(",") if x.strip()]
    except Exception:
        raise argparse.ArgumentTypeError("Invalid --sizes format (comma-separated integers in bytes).")

def main():
    print("Starting crypto benchmark...\n")
    default_out = Path.home() / "Downloads" / "crypto_out"
    parser = argparse.ArgumentParser(description="Benchmark AES and RSA (with optional chunked RSA for big files).")
    parser.add_argument("--out", type=Path, default=default_out, help="Output directory (default: ~/Downloads/crypto_out).")
    parser.add_argument("--sizes", type=parse_sizes, default=[1*100*1000, 1*1000*1000, 10*1000*1000],
                        help="Comma-separated sizes in bytes (e.g. '67108864,268435456').")
    parser.add_argument("--aes-bits", type=int, default=256, choices=[128, 192, 256], help="AES key size.")
    parser.add_argument("--rsa-bits", type=int, default=2048, choices=[2048, 3072, 4096], help="RSA modulus size.")
    parser.add_argument("--include-keygen", action="store_true", help="Measure RSA key generation time.")
    parser.add_argument("--force-direct-rsa-chunked", action="store_true",
                        help="EDUCATIONAL ONLY: use RSA-OAEP in chunks to encrypt/decrypt entire files (slow/inefficient).")
    parser.add_argument("--repeats", type=int, default=3, help="Repeat each measurement N times and store the average duration (default: 3).")
    args = parser.parse_args()

    cfg = Config(
        out_dir=args.out,
        sizes=args.sizes if isinstance(args.sizes, list) else parse_sizes(args.sizes),
        aes_bits=args.aes_bits,
        rsa_bits=args.rsa_bits,
        include_keygen=args.include_keygen,
        force_direct_rsa_chunked=args.force_direct_rsa_chunked,
        repeats=args.repeats,
    )

    print("Configuration done; running benchmarks...")
    rows = run(cfg)
    out_csv = cfg.out_dir / "results.csv"
    write_results(rows, out_csv)

    print(f"\nBenchmark complete. Results saved to: {out_csv}")
    print("Columns: algorithm, operation, file, size_bytes, key_bits, duration_s, throughput_MBps, peak_mem_kB, notes")
    print("\nNotes:")
    print("- Values are averaged over N repeats (see --repeats).")
    print("- Hybrid (RSA+AES) is the correct approach for big files.")
    print("- Chunked RSA is included only to demonstrate how impractical direct RSA is on large data.")

if __name__ == "__main__":
    main()

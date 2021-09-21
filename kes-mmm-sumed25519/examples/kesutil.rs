use kes_mmm_sumed25519::sumed25519 as kes;
use rand::rngs::OsRng;
use std::env::args;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

fn usage(arg0: &String, other: &str) {
    println!("usage: {} <cmd>{}", arg0, other);
    exit(1);
}

const KES_MAGIC: &[u8; 4] = b"KES1";

fn magic_check(file: &mut File) {
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .expect("I/O trying to read magic");
    assert_eq!(&magic, KES_MAGIC)
}

fn magic_read_depth(file: &mut File) -> kes::Depth {
    let mut depth = [0u8; 4];
    file.read_exact(&mut depth)
        .expect("I/O trying to read depth");
    let b = u32::from_be_bytes(depth);
    kes::Depth(b as usize)
}

fn pk_hex(pk: kes::PublicKey) -> String {
    let mut s = String::new();
    for v in pk.as_ref() {
        s.push_str(&format!("{:x}", v))
    }
    s
}

fn sk_read<P: AsRef<Path>>(path: P) -> kes::SecretKey {
    let mut v = Vec::new();
    let mut f = OpenOptions::new()
        .read(true)
        .create_new(false)
        .open(path)
        .expect("cannot open file for reading");
    magic_check(&mut f);
    let depth = magic_read_depth(&mut f);
    f.read_to_end(&mut v).expect("I/O error reading file");

    let sk = kes::SecretKey::from_bytes(depth, &v).expect("not a valid KES secret key");
    sk
}

fn sk_write<P: AsRef<Path>>(path: P, sk: &kes::SecretKey) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("cannot create file");
    f.write_all(KES_MAGIC).expect("cannot write magic");
    f.write_all(&(sk.depth().0 as u32).to_be_bytes())
        .expect("cannot write depth");
    f.write_all(sk.as_ref()).expect("I/O error writing file");
}

fn generate(arg0: &String, args: &[String]) {
    if args.len() < 2 {
        usage(arg0, " <file> <depth>")
    }
    let file = &args[0];
    let depth = args[1]
        .parse::<usize>()
        .expect("cannot convert argument to integer");

    if depth > 16 {
        println!("cannot generate KES key with depth > 16");
    }

    eprintln!("generating key ...");
    let (sk, pk) = kes::generate(&mut OsRng, kes::Depth(depth));

    println!("public key : {}", pk_hex(pk));

    sk_write(file, &sk);
}

fn info(arg0: &String, args: &[String]) {
    if args.len() < 1 {
        usage(arg0, " <file>")
    }

    let file = &args[0];

    let sk = sk_read(file);

    println!("t          : {}", sk.t());
    println!("public key : {}", pk_hex(sk.compute_public()));
    println!("debug");
    println!("  seeds      : {}", sk.rs().len());
    println!("  merkle-pks : {}", sk.merkle_pks().len());
}

fn update(arg0: &String, args: &[String]) {
    if args.len() < 1 {
        usage(arg0, " <file>")
    }

    let file = &args[0];
    let mut sk = sk_read(file);

    if kes::update(&mut sk).is_err() {
        eprintln!("cannot update key");
        return;
    }

    let mut tmpfile = PathBuf::from(file);
    match tmpfile.file_name() {
        None => assert!(false),
        Some(fname) => {
            let mut tmp_filename = std::ffi::OsString::new();
            tmp_filename.push(fname);
            tmp_filename.push(".tmp");
            tmpfile.set_file_name(tmp_filename);
        }
    }
    sk_write(&tmpfile, &sk);
    std::fs::rename(tmpfile, file).expect("cannot rename file");
}

fn debug_exhaust(arg0: &String, args: &[String]) {
    if args.len() < 1 {
        usage(arg0, " <file>")
    }

    let file = &args[0];
    let mut sk = sk_read(file);

    println!(
        "t is {}, number of total iterations {}, remaining iterations {}",
        sk.t(),
        sk.depth().total(),
        sk.depth().total() - sk.t(),
    );

    if sk.t() + 1 == sk.depth().total() {
        println!("key already exhausted");
        return;
    }

    loop {
        println!(
            "t {:5} {:16b} |  #rs {:5}  |  #mpks {:5}",
            sk.t(),
            sk.t(),
            sk.rs().len(),
            sk.merkle_pks().len(),
        );
        assert_eq!(sk.rs().len(), sk.rs_len() as usize);

        if sk.t() + 1 == sk.depth().total() {
            break;
        }
        kes::update(&mut sk).expect("secret key cannot be updated");

        let mut tmpfile = PathBuf::from(file);
        match tmpfile.file_name() {
            None => assert!(false),
            Some(fname) => {
                let mut tmp_filename = std::ffi::OsString::new();
                tmp_filename.push(fname);
                tmp_filename.push(".tmp");
                tmpfile.set_file_name(tmp_filename);
            }
        }
        sk_write(&tmpfile, &sk);
        std::fs::rename(tmpfile, file).expect("cannot rename file");
    }
    println!("key exhausted");
}

pub fn main() {
    let args = args().collect::<Vec<_>>();
    if args.len() < 2 {
        usage(&args[0], "")
    }

    match args[1].as_ref() {
        "generate" => generate(&args[0], &args[2..]),
        "info" => info(&args[0], &args[2..]),
        "update" => update(&args[0], &args[2..]),
        "debug-exhaust" => debug_exhaust(&args[0], &args[2..]),
        s => println!("error: unknown command {}", s),
    }
}

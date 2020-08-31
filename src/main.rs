use clap::Clap;
use rand::Rng;

#[derive(Clap)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    #[clap(version = env!("CARGO_PKG_VERSION"))]
    Password(PasswordOpts),
}

fn get_or_generate<OptsT, F: Fn(OptsT) -> String>(f: F, opts: OptsT) -> String {
    f(opts)
}

#[derive(Clap)]
struct PasswordOpts {
    #[clap(short, long, default_value = "32")]
    length: usize,
}

const PASSWORD_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PASSWORD_FIRST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn generate_password(p: PasswordOpts) -> String {
    let mut result: String = String::new();
    let mut rng = rand::thread_rng();

    result.push(PASSWORD_FIRST_CHARS[rng.gen_range(0, PASSWORD_FIRST_CHARS.len())] as char);

    for _ in 1..p.length {
        result.push(PASSWORD_CHARS[rng.gen_range(0, PASSWORD_CHARS.len())] as char);
    }

    result
}

fn run_password(p: PasswordOpts) {
    println!("Password: {}", get_or_generate(generate_password, p));
}

fn main() {
    let opt = Opts::parse();

    match opt.subcmd {
        SubCommand::Password(p) => {
            run_password(p);
        }
    }
}

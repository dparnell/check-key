use crate::key_checker::{PidGenResult, validate_key};
use clap::{Parser, Subcommand};
use ml_progress::progress;

mod key_checker;

#[derive(Debug, Parser)]
#[command(name = "check-key")]
#[command(author, version)]
#[command(about = "A tool to validate windows product keys", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long)]
    mpc: Option<String>,

    #[arg(long)]
    config: Option<String>
}


#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate the given key
    Validate {
        /// the key to validate
        #[arg(long)]
        key: String
    },

    /// Recover a partial key containing unknown digits
    Recover {
        /// the partial key to recover with '?' character representing unknown characters
        #[arg(long)]
        key: String
    }
}

// the digits used in the base 24 numbering scheme used
const DIGITS: &str = "BCDFGHJKMPQRTVWXY2346789";

struct UnknownChar {
    pub position: usize,
    pub digit: u8
}

fn main() {
    let args = Cli::parse();
    let mpc = args.mpc.unwrap_or(String::from("00000"));
    let config = args.config.unwrap_or(String::from("C:\\Windows\\System32\\spp\\tokens\\pkeyconfig\\pkeyconfig.xrm-ms"));

    match args.command {
        Commands::Validate { key } => {
            match validate_key(key.as_str(), mpc.as_str(), config.as_str()) {
                PidGenResult::Ok => { println!("Key is valid"); }
                PidGenResult::PKeyMissing => { println!("Key missing"); }
                PidGenResult::InvalidArguments => { println!("Invalid arguments"); }
                PidGenResult::InvalidKey => { println!("Invalid key"); }
                PidGenResult::BlackListedKey => { println!("Key is blocked"); }
                PidGenResult::UnknownError(e) => { println!("Unknown error code: {e:?}"); }
            }
        },

        Commands::Recover { key } => {
            let mut unknowns: Vec<UnknownChar> = key.chars().enumerate().filter(|(_idx, ch)|  *ch == '?' ).map(|(idx, _)| UnknownChar {
                position: idx,
                digit: 0
            }).collect();

            let combinations = 24_u64.pow(unknowns.len() as u32);

            let progress = progress!(combinations; bar_fill " " pos "/" total " (" speed "/s " eta ") ").expect("progress");

            let mut key_bytes: Vec<u8> = key.bytes().collect();
            let key_slice = key_bytes.as_mut_slice();
            let digits = DIGITS.as_bytes();

            let mut counter = 0;
            let mut ticks = 1024;
            while counter<combinations {

                let mut carry = true;
                for unknown in unknowns.iter_mut() {
                    key_slice[unknown.position] = digits[unknown.digit as usize];
                    if carry {
                        unknown.digit += 1;
                        carry = unknown.digit == 24;
                        if carry {
                            unknown.digit = 0;
                        }
                    }
                }

                let attempt = String::from_utf8_lossy(key_slice);
                match validate_key(attempt.to_string().as_str(),mpc.as_str(), config.as_str()) {
                    PidGenResult::Ok => {
                        progress.finish_and_clear();
                        println!("\r\nSUCCESS: {:?}", attempt);
                        break;
                    }
                    _ => {
                    }
                }
                counter += 1;
                ticks -= 1;
                if ticks == 0 {
                    progress.inc(1024);
                    ticks = 1024;
                }
            }
            progress.finish_and_clear()
        }
    }
}

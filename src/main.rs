use clap::{crate_version, Parser, Subcommand};
use std::{env, process};
use tensors::{
    commands::{transfer::TransferArgs, CliArgs},
    config::Config,
};

#[derive(Debug, Parser)]
#[command(name="tensors", version=crate_version!(), about="bittensor cli", long_about = "rust implementation of the classic btcli", arg_required_else_help(true))]
struct App {
    /// The subcommand to run
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    cli_args: CliArgs,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Stake,

    #[command(arg_required_else_help = true)]
    Transfer(TransferArgs),
}

#[tokio::main]
async fn main() {
    let mut config = Config::from(Config::figment()).unwrap();

    let args = App::parse();

    config.merge_with_args(&args.cli_args);

    if args.cli_args.config_path.is_some() {
        config.reload_from_path().unwrap();
    }

    // handle commands
    match &args.command {
        Some(Commands::Stake) => {
            println!("Staking with config: {:?}", config);
        }

        Some(Commands::Transfer(transfer_args)) => {
            println!("Transfering with config: {:?}", config);
            println!("Transfering with args: {:?}", transfer_args);
        }
        None => {
            eprintln!("No command provided");
            process::exit(1);
        }
    }
}

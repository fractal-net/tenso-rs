use clap::{crate_version, Parser, Subcommand};
use std::{env, process};
use tensors::{
    commands::{
        create_coldkey::{create_new_coldkey, CreateColdkeyArgs},
        transfer::transfer,
        transfer::TransferArgs,
        CliArgs,
    },
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

    #[command(arg_required_else_help = true)]
    CreateColdkey(CreateColdkeyArgs),
}

#[tokio::main]
async fn main() {
    let mut config = Config::from(Config::figment()).unwrap();

    let args = App::parse();

    config.merge_with_root_cli_args(&args.cli_args);

    if args.cli_args.config_path.is_some() {
        config.reload_from_path().unwrap();
    }

    println!("Config: {:?}", config);

    // handle commands
    match &args.command {
        Some(Commands::Stake) => {
            println!("Staking with config: {:?}", config);
        }

        Some(Commands::Transfer(transfer_args)) => {
            println!("Transfering with config: {:?}", config);
            println!("Transfering with args: {:?}", transfer_args);
            config.merge_with_transfer_args(transfer_args);

            transfer(&config, transfer_args).await.unwrap();
        }

        Some(Commands::CreateColdkey(create_coldkey_args)) => {
            println!("Creating coldkey");
            create_new_coldkey(&config, &create_coldkey_args).unwrap();
        }

        None => {
            eprintln!("No command provided");
            process::exit(1);
        }
    }
}

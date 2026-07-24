use clap::Parser;
use server::common::config::Configuration;
use server::common::config::args::Args;
use server::common::config::telemetry;
use server::database::Db;
use std::process;

fn print_usage() {
  eprintln!("Usage: db <COMMAND>");
  eprintln!();
  eprintln!("Commands:");
  eprintln!("  migrate   Run all pending migrations");
  eprintln!("  seed      Run all database seeds");
  eprintln!("  setup     Run migrations then seeds");
  eprintln!();
  eprintln!("Examples:");
  eprintln!("  cargo run --bin db -- migrate");
  eprintln!("  cargo run --bin db -- seed");
  eprintln!("  cargo run --bin db -- setup");
}

#[tokio::main]
async fn main() {
  let args = Args::parse();

  let Some(command) = args.command.clone() else {
    print_usage();
    process::exit(1);
  };

  if !matches!(command.as_str(), "migrate" | "seed" | "setup") {
    eprintln!("Error: unknown command '{}'\n", command);
    print_usage();
    process::exit(1);
  }

  dotenvy::dotenv().ok();
  telemetry::setup_tracing();

  let cfg = Configuration::from_args(args);

  tracing::info!("Connecting to database...");
  let db = Db::new(&cfg).await.expect("Failed to connect to database");

  match command.as_str() {
    "migrate" => {
      tracing::info!("Running migrations...");
      db.run_migrations().await.expect("Failed to run migrations");
      tracing::info!("Migrations completed successfully");
    }
    "seed" => {
      tracing::info!("Running seeds...");
      db.run_seeds(&cfg).await.expect("Failed to run seeds");
      tracing::info!("Seeds completed successfully");
    }
    "setup" => {
      tracing::info!("Running migrations...");
      db.run_migrations().await.expect("Failed to run migrations");
      tracing::info!("Migrations completed successfully");

      tracing::info!("Running seeds...");
      db.run_seeds(&cfg).await.expect("Failed to run seeds");
      tracing::info!("Seeds completed successfully");
    }
    _ => unreachable!(),
  }
}

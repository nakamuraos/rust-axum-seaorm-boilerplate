use server::common::config::telemetry;
use server::common::config::Configuration;
use server::database::Db;
use std::env;
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
  let args: Vec<String> = env::args().collect();

  if args.len() < 2 {
    print_usage();
    process::exit(1);
  }

  let command = args[1].as_str();

  if !matches!(command, "migrate" | "seed" | "setup") {
    eprintln!("Error: unknown command '{}'\n", command);
    print_usage();
    process::exit(1);
  }

  dotenvy::dotenv().ok();
  telemetry::setup_tracing();

  let cfg = Configuration::new();

  tracing::info!("Connecting to database...");
  let db = Db::new(&cfg).await.expect("Failed to connect to database");

  match command {
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

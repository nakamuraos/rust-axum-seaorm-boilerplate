use clap::Parser;
use server::common::config::Configuration;
use server::common::config::args::Args;
use server::common::config::shutdown::shutdown_signal;
use server::common::config::telemetry;
use server::database::Db;
use server::workers::{Job, JobContext, jobs, run_once};
use std::process;

/// Runs the background jobs registered in `server::workers::jobs`.
///
/// A job performs one run and the process exits, so it can be driven by cron or
/// a scheduler. Passing `--watch` keeps the process alive and repeats the job on
/// its own interval instead.
#[derive(Parser, Debug)]
#[command(version, about = "Axum + SeaORM background workers", long_about = None)]
struct WorkerArgs {
  #[command(flatten)]
  config: Args,

  /// Keep running and repeat the job on its interval
  #[arg(long)]
  watch: bool,

  /// List the available jobs and exit
  #[arg(long)]
  list: bool,
}

fn print_usage() {
  eprintln!("Usage: worker <JOB|all> [--watch]");
  eprintln!();
  eprintln!("Jobs:");
  print_jobs();
  eprintln!();
  eprintln!("Examples:");
  eprintln!("  cargo run --bin worker -- cleanup-tokens");
  eprintln!("  cargo run --bin worker -- all --watch");
}

fn print_jobs() {
  let width = jobs::registry()
    .iter()
    .map(|job| job.name().len())
    .max()
    .unwrap_or(0);

  for job in jobs::registry() {
    eprintln!(
      "  {:<width$}   {}",
      job.name(),
      job.description(),
      width = width
    );
  }
}

#[tokio::main]
async fn main() {
  let args = WorkerArgs::parse();

  if args.list {
    print_jobs();
    return;
  }

  let Some(name) = args.config.command.clone() else {
    print_usage();
    process::exit(1);
  };

  // `all` runs the whole registry, which is what a single scheduled entry for
  // every background job looks like.
  let selected: Vec<Box<dyn Job>> = if name == "all" {
    jobs::registry()
  } else {
    match jobs::find(&name) {
      Some(job) => vec![job],
      None => {
        eprintln!("Error: unknown job '{}'\n", name);
        print_usage();
        process::exit(1);
      }
    }
  };

  dotenvy::dotenv().ok();
  telemetry::setup_tracing();

  let cfg = Configuration::from_args(args.config);
  let db = Db::new(&cfg).await.expect("Failed to connect to database");
  let ctx = JobContext { db, cfg };

  if !args.watch {
    for job in &selected {
      run_once(job.as_ref(), &ctx).await;
    }
    return;
  }

  // Each job keeps its own schedule, so one slow interval does not hold back
  // the others.
  let mut handles = Vec::new();
  for job in selected {
    let ctx = ctx.clone();
    handles.push(tokio::spawn(async move {
      let interval = job.interval(&ctx.cfg);
      tracing::info!(job = job.name(), ?interval, "Watching job");

      loop {
        run_once(job.as_ref(), &ctx).await;
        tokio::time::sleep(interval).await;
      }
    }));
  }

  shutdown_signal().await;
  tracing::info!("Shutting down worker");

  for handle in handles {
    handle.abort();
  }
}

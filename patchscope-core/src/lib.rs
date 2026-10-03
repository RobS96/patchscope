//! patchscope-core: discover what a machine runs, research what is wrong
//! with it, plan the updates that fix it, and apply them safely.
//!
//! ```no_run
//! use patchscope_core::{analysis, discover, exec::SystemRunner, plan, policy::Policy, research::http::UreqClient};
//!
//! let runner = SystemRunner::new();
//! let report = discover::discover(&runner, &Default::default(), &|_| {});
//! let analysis = analysis::analyze(&report, &UreqClient::new(), &Default::default(), &|_| {});
//! let plan = plan::build_plan(&report, &analysis, &Policy::default(), &plan::Selection::All);
//! println!("{} actions planned", plan.actions.len());
//! ```

#![forbid(unsafe_code)]

pub mod analysis;
pub mod apply;
pub mod discover;
pub mod exec;
pub mod managers;
pub mod model;
pub mod paths;
pub mod plan;
pub mod policy;
pub mod report;
pub mod research;
pub mod util;

/// The crate version, shown by both front ends.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

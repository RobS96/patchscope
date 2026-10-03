//! Discovery: build a [`SystemReport`] for this machine. Read-only and
//! unprivileged; nothing here changes the system.

pub mod hardware;
pub mod os;
pub mod runtimes;

use crate::exec::{CommandRunner, is_elevated};
use crate::managers::{self, Context};
use crate::model::{HostInfo, ManagerId, SCHEMA_VERSION, SystemReport};
use crate::util;

#[derive(Debug, Clone, Default)]
pub struct DiscoverOptions {
    /// Include hostname, serial numbers and MAC addresses. Off by default
    /// so a report can be shared without identifying the machine.
    pub include_identifiers: bool,
    /// Only these managers (all when empty).
    pub only_managers: Vec<ManagerId>,
    /// Never query these managers.
    pub skip_managers: Vec<ManagerId>,
}

/// Progress messages for a UI ("Querying Homebrew…").
pub type Progress<'a> = &'a (dyn Fn(&str) + Sync);

pub fn discover(runner: &dyn CommandRunner, opts: &DiscoverOptions, progress: Progress) -> SystemReport {
    let mut warnings = Vec::new();
    progress("Identifying the operating system…");
    let os = os::detect(runner, &mut warnings);
    progress("Reading hardware…");
    let hardware = hardware::detect(runner, opts.include_identifiers, &mut warnings);
    progress("Looking for language runtimes…");
    let runtimes = runtimes::detect(runner);

    let ctx = Context::new(os.clone());
    let selected: Vec<Box<dyn managers::Manager>> = managers::all()
        .into_iter()
        .filter(|m| opts.only_managers.is_empty() || opts.only_managers.contains(&m.id()))
        .filter(|m| !opts.skip_managers.contains(&m.id()))
        .collect();

    // Managers are independent and some are slow (Software Update and
    // Windows Update contact the vendor), so they are queried in parallel.
    let mut inventories = std::thread::scope(|s| {
        let handles: Vec<_> = selected
            .iter()
            .map(|m| {
                let ctx = &ctx;
                s.spawn(move || {
                    if m.supported_on(ctx.os.family) && runner.which(m.program()).is_some() {
                        progress(&format!("Querying {}…", m.id().display_name()));
                    }
                    managers::inventory(m.as_ref(), runner, ctx)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect::<Vec<_>>()
    });
    inventories.sort_by_key(|i| i.id);
    for inv in &inventories {
        if let Some(e) = &inv.error {
            warnings.push(format!("{}: {e}", inv.id.display_name()));
        }
    }

    let hostname = opts.include_identifiers.then(sysinfo::System::host_name).flatten();
    progress("Discovery complete.");
    SystemReport {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: util::now_rfc3339(),
        host: HostInfo {
            hostname,
            uptime_secs: sysinfo::System::uptime(),
            is_elevated: is_elevated(runner),
        },
        os,
        hardware,
        runtimes,
        managers: inventories,
        warnings,
    }
}

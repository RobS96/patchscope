//! What the app asks of the system, behind a trait so the UI tests drive
//! the real app against recorded results.

use patchscope_core::analysis::{AnalyzeOptions, analyze};
use patchscope_core::apply::{ApplyEvent, ApplyOptions, ApplyReport, apply_plan};
use patchscope_core::discover::{DiscoverOptions, discover};
use patchscope_core::exec::SystemRunner;
use patchscope_core::model::{ManagerId, OsInfo, Scan};
use patchscope_core::plan::UpdatePlan;
use patchscope_core::research::http::UreqClient;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanSettings {
    pub offline: bool,
    pub include_identifiers: bool,
    pub skip: Vec<ManagerId>,
}

pub type Progress<'a> = &'a (dyn Fn(&str) + Sync);

pub trait Backend: Send + Sync {
    fn scan(&self, settings: &ScanSettings, progress: Progress) -> Result<Scan, String>;
    fn apply(
        &self,
        plan: &UpdatePlan,
        os: &OsInfo,
        opts: &ApplyOptions,
        progress: Progress,
    ) -> Result<ApplyReport, String>;
}

pub struct RealBackend;

impl Backend for RealBackend {
    fn scan(&self, s: &ScanSettings, progress: Progress) -> Result<Scan, String> {
        let runner = SystemRunner::new();
        let report = discover(
            &runner,
            &DiscoverOptions {
                include_identifiers: s.include_identifiers,
                only_managers: Vec::new(),
                skip_managers: s.skip.clone(),
            },
            progress,
        );
        let analysis = analyze(
            &report,
            &UreqClient::new(),
            &AnalyzeOptions {
                offline: s.offline,
                ..Default::default()
            },
            progress,
        );
        Ok(Scan { report, analysis })
    }

    fn apply(
        &self,
        plan: &UpdatePlan,
        os: &OsInfo,
        opts: &ApplyOptions,
        progress: Progress,
    ) -> Result<ApplyReport, String> {
        let runner = SystemRunner::new();
        apply_plan(plan, os, &runner, opts, &|e| match e {
            ApplyEvent::Started {
                index,
                total,
                action,
                command,
            } => {
                progress(&format!("[{}/{}] {}", index + 1, total, action.title));
                progress(&format!("    $ {command}"));
            }
            ApplyEvent::Finished { result, .. } => {
                progress(&format!("    → {} ({})", result.status.label(), result.message))
            }
            ApplyEvent::Verifying(m) => progress(&format!("Verifying {}…", m.display_name())),
            ApplyEvent::Warning(w) => progress(&format!("Warning: {w}")),
        })
        .map_err(|e| e.to_string())
    }
}

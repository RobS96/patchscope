//! Hardware inventory: portable facts from `sysinfo`, then the vendor's own
//! tool for model, firmware, GPU and battery details.

use crate::exec::{CommandRunner, CommandSpec, windows_powershell_program};
use crate::model::{BatteryInfo, CpuInfo, DiskInfo, HardwareInfo, MemoryInfo, NetworkInterface, OsFamily, Temperature};
use serde_json::Value;
use std::time::Duration;
use sysinfo::{Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System};

pub fn detect(runner: &dyn CommandRunner, include_identifiers: bool, warnings: &mut Vec<String>) -> HardwareInfo {
    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    let cpus = sys.cpus();
    let cpu = CpuInfo {
        brand: cpus.first().map(|c| c.brand().trim().to_string()).unwrap_or_default(),
        vendor: cpus.first().map(|c| c.vendor_id().to_string()).unwrap_or_default(),
        arch: System::cpu_arch(),
        physical_cores: System::physical_core_count(),
        logical_cores: cpus.len(),
        frequency_mhz: cpus.first().map(|c| c.frequency()).unwrap_or(0),
    };
    let memory = MemoryInfo {
        total_bytes: sys.total_memory(),
        available_bytes: sys.available_memory(),
        swap_total_bytes: sys.total_swap(),
        swap_used_bytes: sys.used_swap(),
    };
    let disks = Disks::new_with_refreshed_list()
        .list()
        .iter()
        .map(|d| DiskInfo {
            name: d.name().to_string_lossy().into_owned(),
            mount_point: d.mount_point().to_string_lossy().into_owned(),
            file_system: d.file_system().to_string_lossy().into_owned(),
            kind: format!("{:?}", d.kind()),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
            removable: d.is_removable(),
        })
        .filter(|d| d.total_bytes > 0 && !is_noise_mount(&d.mount_point))
        .collect();
    let mut network_interfaces: Vec<NetworkInterface> = Networks::new_with_refreshed_list()
        .iter()
        .map(|(name, data)| NetworkInterface {
            name: name.clone(),
            mac_address: include_identifiers.then(|| data.mac_address().to_string()),
        })
        .collect();
    network_interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    let temperatures = Components::new_with_refreshed_list()
        .iter()
        .filter_map(|c| {
            c.temperature()
                .filter(|t| t.is_finite() && *t > 0.0)
                .map(|t| Temperature {
                    label: c.label().to_string(),
                    celsius: t,
                })
        })
        .collect();

    let mut hw = HardwareInfo {
        cpu,
        memory,
        disks,
        network_interfaces,
        temperatures,
        ..Default::default()
    };
    match OsFamily::current() {
        OsFamily::Macos => macos(runner, &mut hw, warnings),
        OsFamily::Linux => linux(runner, &mut hw),
        OsFamily::Windows => windows(runner, &mut hw, warnings),
        OsFamily::Other => {}
    }
    if !include_identifiers {
        hw.serial = None;
    }
    hw
}

/// Pseudo and per-app mounts that say nothing about the machine.
fn is_noise_mount(m: &str) -> bool {
    // macOS: "/" reports the APFS container's space; the Data, VM,
    // Preboot … volumes share it and would repeat the same numbers.
    m.starts_with("/System/Volumes/")
        || m.starts_with("/snap/")
        || m.starts_with("/var/lib/docker")
        || m.starts_with("/run/")
        || m.starts_with("/dev")
        || m.starts_with("/Library/Developer/CoreSimulator")
}

fn macos(runner: &dyn CommandRunner, hw: &mut HardwareInfo, warnings: &mut Vec<String>) {
    let out = runner.run(
        &CommandSpec::new(
            "system_profiler",
            &[
                "-json",
                "-detailLevel",
                "mini",
                "SPHardwareDataType",
                "SPDisplaysDataType",
                "SPPowerDataType",
            ],
        )
        .timeout(Duration::from_secs(90)),
    );
    match out {
        Ok(o) if o.success() => apply_system_profiler(&o.stdout, hw).unwrap_or_else(|e| warnings.push(e)),
        Ok(o) => warnings.push(format!("system_profiler failed: {}", o.tail(200))),
        Err(e) => warnings.push(format!("system_profiler: {e}")),
    }
    if hw.model.is_none()
        && let Ok(o) = runner.run(&CommandSpec::new("sysctl", &["-n", "hw.model"]).timeout(Duration::from_secs(10)))
        && o.success()
        && !o.stdout.trim().is_empty()
    {
        hw.vendor = Some("Apple".into());
        hw.model = Some(o.stdout.trim().to_string());
    }
}

pub fn apply_system_profiler(json: &str, hw: &mut HardwareInfo) -> Result<(), String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("system_profiler JSON: {e}"))?;
    // system_profiler says "Unknown" when it cannot read a value.
    let s = |x: &Value, k: &str| {
        x.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|v| !v.is_empty() && v != "Unknown")
    };
    if let Some(h) = v.get("SPHardwareDataType").and_then(|a| a.get(0)) {
        hw.vendor = Some("Apple".into());
        hw.model = match (s(h, "machine_name"), s(h, "machine_model")) {
            (Some(n), Some(m)) => Some(format!("{n} ({m})")),
            (n, m) => n.or(m),
        };
        hw.serial = s(h, "serial_number");
        hw.firmware = s(h, "boot_rom_version");
        if hw.cpu.brand.is_empty() {
            hw.cpu.brand = s(h, "chip_type").or_else(|| s(h, "cpu_type")).unwrap_or_default();
        }
    }
    if let Some(ds) = v.get("SPDisplaysDataType").and_then(Value::as_array) {
        hw.gpus = ds
            .iter()
            .filter_map(|d| s(d, "sppci_model").or_else(|| s(d, "_name")))
            .collect();
    }
    if let Some(ps) = v.get("SPPowerDataType").and_then(Value::as_array)
        && let Some(health) = ps.iter().find_map(|p| p.get("sppower_battery_health_info"))
    {
        hw.battery = Some(BatteryInfo {
            cycle_count: health
                .get("sppower_battery_cycle_count")
                .and_then(Value::as_u64)
                .map(|c| c as u32),
            condition: s(health, "sppower_battery_health"),
            max_capacity_percent: s(health, "sppower_battery_health_maximum_capacity")
                .and_then(|p| p.trim_end_matches('%').parse().ok()),
        });
    }
    Ok(())
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "To Be Filled By O.E.M." && s != "Default string")
}

fn linux(runner: &dyn CommandRunner, hw: &mut HardwareInfo) {
    hw.vendor = read_trim("/sys/class/dmi/id/sys_vendor");
    hw.model = match (
        read_trim("/sys/class/dmi/id/product_name"),
        read_trim("/sys/class/dmi/id/product_version"),
    ) {
        (Some(n), Some(v)) if v != "None" && !n.contains(&v) => Some(format!("{n} {v}")),
        (n, _) => n,
    };
    hw.serial = read_trim("/sys/class/dmi/id/product_serial"); // root-only on most systems
    hw.firmware = match (
        read_trim("/sys/class/dmi/id/bios_version"),
        read_trim("/sys/class/dmi/id/bios_date"),
    ) {
        (Some(v), Some(d)) => Some(format!("{v} ({d})")),
        (v, _) => v,
    };
    if let Ok(o) = runner.run(&CommandSpec::new("lspci", &[]).timeout(Duration::from_secs(20)))
        && o.success()
    {
        hw.gpus = parse_lspci_gpus(&o.stdout);
    }
    for bat in ["BAT0", "BAT1"] {
        let base = format!("/sys/class/power_supply/{bat}");
        if std::path::Path::new(&base).exists() {
            let num = |f: &str| read_trim(&format!("{base}/{f}")).and_then(|s| s.parse::<u64>().ok());
            let full = num("energy_full").or_else(|| num("charge_full"));
            let design = num("energy_full_design").or_else(|| num("charge_full_design"));
            hw.battery = Some(BatteryInfo {
                cycle_count: num("cycle_count").map(|c| c as u32).filter(|c| *c > 0),
                condition: read_trim(&format!("{base}/health")),
                max_capacity_percent: match (full, design) {
                    (Some(f), Some(d)) if d > 0 => Some((f * 100 / d) as u32),
                    _ => None,
                },
            });
            break;
        }
    }
}

pub fn parse_lspci_gpus(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| {
            l.contains("VGA compatible controller") || l.contains("3D controller") || l.contains("Display controller")
        })
        .filter_map(|l| l.split_once(": ").map(|(_, s)| s.trim().to_string()))
        .collect()
}

const WIN_HW_PS: &str = r#"$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
[pscustomobject]@{
  vendor = $cs.Manufacturer; model = $cs.Model
  serial = $bios.SerialNumber; firmware = ($bios.SMBIOSBIOSVersion + ' (' + $bios.ReleaseDate.ToString('yyyy-MM-dd') + ')')
  gpus = $gpu
} | ConvertTo-Json -Compress"#;

fn windows(runner: &dyn CommandRunner, hw: &mut HardwareInfo, warnings: &mut Vec<String>) {
    let out = runner.run(
        &CommandSpec::new(
            &windows_powershell_program(),
            &["-NoProfile", "-NonInteractive", "-Command", WIN_HW_PS],
        )
        .timeout(Duration::from_secs(90)),
    );
    match out {
        Ok(o) if o.success() => apply_windows_cim(&o.stdout, hw).unwrap_or_else(|e| warnings.push(e)),
        Ok(o) => warnings.push(format!("hardware query failed: {}", o.tail(200))),
        Err(e) => warnings.push(format!("hardware query: {e}")),
    }
}

pub fn apply_windows_cim(json: &str, hw: &mut HardwareInfo) -> Result<(), String> {
    let v: Value = serde_json::from_str(json.trim()).map_err(|e| format!("hardware JSON: {e}"))?;
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
    };
    hw.vendor = s("vendor");
    hw.model = s("model");
    hw.serial = s("serial");
    hw.firmware = s("firmware");
    hw.gpus = match v.get("gpus") {
        Some(Value::Array(a)) => a.iter().filter_map(|g| g.as_str().map(str::to_string)).collect(),
        Some(Value::String(g)) => vec![g.clone()],
        _ => Vec::new(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_profiler_unknowns_are_dropped() {
        let mut hw = HardwareInfo::default();
        apply_system_profiler(r#"{"SPHardwareDataType":[{"machine_name":"Unknown","machine_model":"Unknown","boot_rom_version":"2103"}]}"#, &mut hw).unwrap();
        assert_eq!(hw.model, None);
        assert_eq!(hw.firmware.as_deref(), Some("2103"));
    }

    #[test]
    fn system_profiler_json() {
        let json = r#"{"SPHardwareDataType":[{"machine_name":"MacBook Pro","machine_model":"MacBookPro16,1","serial_number":"C02XXXXXXX","boot_rom_version":"2103.0.0.0.0 (iBridge: 23.16.0.0.0)","cpu_type":"8-Core Intel Core i9"}],
            "SPDisplaysDataType":[{"_name":"Intel UHD Graphics 630","sppci_model":"Intel UHD Graphics 630"},{"_name":"AMD Radeon Pro 5500M","sppci_model":"AMD Radeon Pro 5500M"}],
            "SPPowerDataType":[{"_name":"spbattery_information","sppower_battery_health_info":{"sppower_battery_cycle_count":412,"sppower_battery_health":"Good","sppower_battery_health_maximum_capacity":"87%"}}]}"#;
        let mut hw = HardwareInfo::default();
        apply_system_profiler(json, &mut hw).unwrap();
        assert_eq!(hw.model.as_deref(), Some("MacBook Pro (MacBookPro16,1)"));
        assert_eq!(hw.firmware.as_deref(), Some("2103.0.0.0.0 (iBridge: 23.16.0.0.0)"));
        assert_eq!(hw.gpus.len(), 2);
        let b = hw.battery.unwrap();
        assert_eq!((b.cycle_count, b.max_capacity_percent), (Some(412), Some(87)));
        assert_eq!(hw.cpu.brand, "8-Core Intel Core i9");
    }

    #[test]
    fn lspci() {
        let t = "00:02.0 VGA compatible controller: Intel Corporation UHD Graphics 620 (rev 07)\n\
                 01:00.0 3D controller: NVIDIA Corporation GP108M [GeForce MX150] (rev a1)\n\
                 00:1f.3 Audio device: Intel Corporation Sunrise Point-LP HD Audio (rev 21)\n";
        assert_eq!(parse_lspci_gpus(t).len(), 2);
    }

    #[test]
    fn windows_cim_single_gpu_is_a_string() {
        let mut hw = HardwareInfo::default();
        apply_windows_cim(
            r#"{"vendor":"Dell Inc.","model":"Latitude 7440","serial":"ABC123","firmware":"1.18.0 (2025-06-01)","gpus":"Intel(R) Iris(R) Xe Graphics"}"#,
            &mut hw,
        )
        .unwrap();
        assert_eq!(hw.gpus, ["Intel(R) Iris(R) Xe Graphics"]);
        assert_eq!(hw.vendor.as_deref(), Some("Dell Inc."));
    }

    #[test]
    fn noise_mounts() {
        assert!(is_noise_mount("/System/Volumes/VM"));
        assert!(is_noise_mount("/System/Volumes/Data"));
        assert!(!is_noise_mount("/"));
        assert!(is_noise_mount("/snap/core22/1234"));
    }
}

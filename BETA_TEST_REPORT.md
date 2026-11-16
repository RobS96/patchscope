# CLI Tools Beta Testing Report

- **Host:** ghost (ThinkPad T490)
- **OS / Kernel:** Ubuntu 24.04.2 LTS (`6.8.0-149-generic`)
- **patchscope:** Scanned 1,269 packages; remediated 128 security updates; configured `min_severity = "high"` and `security_only = true` with daily systemd timer.
- **il:** Generated ML-DSA-87 keypair for `ghost.local`; verified sealed envelope (`conf=low integ=high avail=high`).
- **morse:** Verified strict encoding (`morse encode "OK" --strict`).

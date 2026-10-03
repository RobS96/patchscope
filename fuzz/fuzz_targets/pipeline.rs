#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| patchscope_core::fuzzing::pipeline(data));

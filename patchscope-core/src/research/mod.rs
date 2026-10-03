//! The public data sources patchscope researches against. Each is optional:
//! when one is unreachable the analysis says so and carries on with the rest.

pub mod eol;
pub mod epss;
pub mod http;
pub mod kev;
pub mod osv;

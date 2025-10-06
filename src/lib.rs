// Professional modular structure - ENABLED!
pub mod core;
pub mod providers;
pub mod specs;  
pub mod testing;
pub mod cli;
pub mod utils;
pub mod security;
pub mod reports;
pub mod fuzzing;

// Legacy compatibility exports
pub use providers::legacy as ai;

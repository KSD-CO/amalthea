use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
    Both,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Csv => write!(f, "csv"),
            ExportFormat::Both => write!(f, "both"),
        }
    }
}

fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .with_utc_timestamps()
        .init()?;

    oidc_rp::dummy::dummy(&"Some arg".to_string());

    Ok(())
}

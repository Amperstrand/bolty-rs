use anyhow::Context;
use ntag424::{Session, Transport};

pub async fn cmd_ver<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let session = Session::default();
    let v = session
        .get_version(transport)
        .await
        .context("failed to read version")?;

    println!("Hardware:");
    println!("  Vendor ID: 0x{:02X}", v.hw_vendor_id());
    println!("  Type:      0x{:02X}", v.hw_type());
    println!(
        "  Version:   {:02X}.{:02X}",
        v.hw_major_version(),
        v.hw_minor_version()
    );
    println!("Software:");
    println!("  Vendor ID: 0x{:02X}", v.sw_vendor_id());
    println!("  Type:      0x{:02X}", v.sw_type());
    println!(
        "  Version:   {:02X}.{:02X}",
        v.sw_major_version(),
        v.sw_minor_version()
    );
    println!("Production:");
    println!("  Batch:     {}", v.batch_number());
    println!(
        "  Date:      CW{} {}",
        v.calendar_week_of_production(),
        v.calendar_year_of_production()
    );

    let is_ntag424 = v.hw_vendor_id() == 0x04 && v.hw_type() == 0x04;
    if is_ntag424 {
        println!("\nCard type: NTAG424 DNA (confirmed)");
    } else {
        println!(
            "\nCard type: Unknown (vendor={:02X} type={:02X})",
            v.hw_vendor_id(),
            v.hw_type()
        );
    }

    Ok(())
}

fn main() {
    println!("cargo::rustc-check-cfg=cfg(esp_idf_comp_mdns_enabled)");
    println!("cargo::rustc-check-cfg=cfg(esp_idf_comp_espressif__mdns_enabled)");

    // Reproducible build stamp (#62): the embedded epoch is pinned from the
    // env (BOLTY_BUILD_EPOCH, falling back to the standard SOURCE_DATE_EPOCH),
    // never the wall clock. Default "0" means "unstamped" — two builds of the
    // same commit with no env set are byte-identical. Consumed via
    // `env!("BOLTY_BUILD_EPOCH")` (crate::firmware::BUILD_EPOCH).
    let build_epoch = std::env::var("BOLTY_BUILD_EPOCH")
        .or_else(|_| std::env::var("SOURCE_DATE_EPOCH"))
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo::rustc-env=BOLTY_BUILD_EPOCH={build_epoch}");
    println!("cargo::rerun-if-env-changed=BOLTY_BUILD_EPOCH");
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");

    embuild::espidf::sysenv::output();
}

use esp_idf_svc::tls::X509;

fn load_pair() -> Option<(X509<'static>, X509<'static>)> {
    let (cert_der, key_der) = crate::firmware::nvs::load_cert_der()?;

    let cert_static: &'static [u8] = Box::leak(cert_der.into_boxed_slice());
    let key_static: &'static [u8] = Box::leak(key_der.into_boxed_slice());

    Some((X509::der(cert_static), X509::der(key_static)))
}

pub fn server_cert_and_key() -> Option<(X509<'static>, X509<'static>)> {
    load_pair()
}

pub fn is_provisioned() -> bool {
    crate::firmware::nvs::has_cert()
}

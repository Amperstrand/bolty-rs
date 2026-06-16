use esp_idf_sys::{
    self as sys, ESP_OK, mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_free, mbedtls_ctr_drbg_init,
    mbedtls_ctr_drbg_random, mbedtls_ctr_drbg_seed, mbedtls_entropy_context, mbedtls_entropy_free,
    mbedtls_entropy_func, mbedtls_entropy_init, mbedtls_md_type_t_MBEDTLS_MD_SHA256,
    mbedtls_pk_context, mbedtls_pk_free, mbedtls_pk_info_from_type, mbedtls_pk_init,
    mbedtls_pk_setup, mbedtls_pk_type_t_MBEDTLS_PK_RSA, mbedtls_rsa_context, mbedtls_rsa_gen_key,
    mbedtls_x509write_cert, mbedtls_x509write_crt_der, mbedtls_x509write_crt_free,
    mbedtls_x509write_crt_init, mbedtls_x509write_crt_set_authority_key_identifier,
    mbedtls_x509write_crt_set_basic_constraints, mbedtls_x509write_crt_set_issuer_key,
    mbedtls_x509write_crt_set_issuer_name, mbedtls_x509write_crt_set_md_alg,
    mbedtls_x509write_crt_set_serial_raw, mbedtls_x509write_crt_set_subject_key,
    mbedtls_x509write_crt_set_subject_key_identifier, mbedtls_x509write_crt_set_subject_name,
    mbedtls_x509write_crt_set_validity, mbedtls_x509write_crt_set_version,
};

const RSA_KEY_BITS: core::ffi::c_uint = 2048;
const RSA_EXPONENT: core::ffi::c_int = 65537;
const DER_BUF_SIZE: usize = 4096;

pub struct CertGenError {
    pub code: core::ffi::c_int,
    pub context: &'static str,
}

impl core::fmt::Display for CertGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cert generation failed at {} (mbedTLS error {:#x})",
            self.context, self.code
        )
    }
}

fn err(code: core::ffi::c_int, context: &'static str) -> CertGenError {
    CertGenError { code, context }
}

/// Generate an RSA-2048 self-signed certificate and private key (both DER).
///
/// Uses the ESP32 hardware RNG (via mbedTLS entropy) so the private key
/// never leaves the device.  The caller stores the result in NVS.
pub fn generate_self_signed_cert() -> Result<(std::vec::Vec<u8>, std::vec::Vec<u8>), CertGenError> {
    unsafe {
        // ------------------------------------------------------------------
        // 1. Entropy + CTR_DRBG (RNG pipeline)
        // ------------------------------------------------------------------
        let mut entropy: mbedtls_entropy_context = core::mem::zeroed();
        mbedtls_entropy_init(&mut entropy);

        let mut ctr_drbg: mbedtls_ctr_drbg_context = core::mem::zeroed();
        mbedtls_ctr_drbg_init(&mut ctr_drbg);

        let seed_label = b"bolty_cert_gen\0";
        let rc = mbedtls_ctr_drbg_seed(
            &mut ctr_drbg,
            Some(mbedtls_entropy_func),
            &mut entropy as *mut _ as *mut core::ffi::c_void,
            seed_label.as_ptr(),
            seed_label.len(),
        );
        if rc != ESP_OK {
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "ctr_drbg_seed"));
        }

        // ------------------------------------------------------------------
        // 2. PK context + RSA key generation
        // ------------------------------------------------------------------
        let mut pk: mbedtls_pk_context = core::mem::zeroed();
        mbedtls_pk_init(&mut pk);

        let rsa_info = mbedtls_pk_info_from_type(mbedtls_pk_type_t_MBEDTLS_PK_RSA);
        if rsa_info.is_null() {
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(-1, "pk_info_from_type"));
        }

        let rc = mbedtls_pk_setup(&mut pk, rsa_info);
        if rc != ESP_OK {
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "pk_setup"));
        }

        let rsa_ctx = pk.private_pk_ctx as *mut mbedtls_rsa_context;
        let rc = mbedtls_rsa_gen_key(
            rsa_ctx,
            Some(mbedtls_ctr_drbg_random),
            &mut ctr_drbg as *mut _ as *mut core::ffi::c_void,
            RSA_KEY_BITS,
            RSA_EXPONENT,
        );
        if rc != ESP_OK {
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "rsa_gen_key"));
        }

        // ------------------------------------------------------------------
        // 3. X.509 certificate assembly
        // ------------------------------------------------------------------
        let mut crt: mbedtls_x509write_cert = core::mem::zeroed();
        mbedtls_x509write_crt_init(&mut crt);

        mbedtls_x509write_crt_set_version(&mut crt, 2);

        let mut serial = [0u8; 16];
        sys::esp_fill_random(serial.as_mut_ptr().cast(), serial.len());
        if serial[0] & 0x80 != 0 {
            serial[0] &= 0x7f;
        }
        let rc = mbedtls_x509write_crt_set_serial_raw(&mut crt, serial.as_mut_ptr(), serial.len());
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_serial_raw"));
        }

        let rc = mbedtls_x509write_crt_set_validity(
            &mut crt,
            c"20260101000000".as_ptr(),
            c"20360101000000".as_ptr(),
        );
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_validity"));
        }

        let rc = mbedtls_x509write_crt_set_issuer_name(&mut crt, c"CN=bolty".as_ptr());
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_issuer_name"));
        }

        let rc = mbedtls_x509write_crt_set_subject_name(&mut crt, c"CN=bolty".as_ptr());
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_subject_name"));
        }

        mbedtls_x509write_crt_set_subject_key(&mut crt, &mut pk);
        mbedtls_x509write_crt_set_issuer_key(&mut crt, &mut pk);
        mbedtls_x509write_crt_set_md_alg(&mut crt, mbedtls_md_type_t_MBEDTLS_MD_SHA256);

        let rc = mbedtls_x509write_crt_set_subject_key_identifier(&mut crt);
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_subject_key_id"));
        }

        let rc = mbedtls_x509write_crt_set_authority_key_identifier(&mut crt);
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_auth_key_id"));
        }

        let rc = mbedtls_x509write_crt_set_basic_constraints(&mut crt, 0, -1);
        if rc != ESP_OK {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(rc, "set_basic_constraints"));
        }

        // ------------------------------------------------------------------
        // 4. Serialize certificate to DER
        // ------------------------------------------------------------------
        let mut cert_buf = [0u8; DER_BUF_SIZE];
        let written = mbedtls_x509write_crt_der(
            &mut crt,
            cert_buf.as_mut_ptr(),
            cert_buf.len(),
            Some(mbedtls_ctr_drbg_random),
            &mut ctr_drbg as *mut _ as *mut core::ffi::c_void,
        );
        if written < 0 {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(written, "x509write_crt_der"));
        }
        let cert_len = written as usize;
        let cert_der = cert_buf[cert_buf.len() - cert_len..].to_vec();

        // ------------------------------------------------------------------
        // 5. Serialize private key to DER
        // ------------------------------------------------------------------
        let mut key_buf = [0u8; DER_BUF_SIZE];
        let written = sys::mbedtls_pk_write_key_der(&pk, key_buf.as_mut_ptr(), key_buf.len());
        if written < 0 {
            mbedtls_x509write_crt_free(&mut crt);
            mbedtls_pk_free(&mut pk);
            mbedtls_ctr_drbg_free(&mut ctr_drbg);
            mbedtls_entropy_free(&mut entropy);
            return Err(err(written, "pk_write_key_der"));
        }
        let key_len = written as usize;
        let key_der = key_buf[key_buf.len() - key_len..].to_vec();

        // ------------------------------------------------------------------
        // 6. Cleanup
        // ------------------------------------------------------------------
        mbedtls_x509write_crt_free(&mut crt);
        mbedtls_pk_free(&mut pk);
        mbedtls_ctr_drbg_free(&mut ctr_drbg);
        mbedtls_entropy_free(&mut entropy);

        Ok((cert_der, key_der))
    }
}

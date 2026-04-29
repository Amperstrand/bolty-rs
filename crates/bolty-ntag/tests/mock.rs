use aes::{
    Aes128,
    cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use cmac::{Cmac, Mac};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use ntag424::{Response, Transport};

pub const UID: [u8; 7] = [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80];
const TI: [u8; 4] = [0x08, 0x5B, 0xC9, 0x41];
const DEFAULT_FILE_SETTINGS: [u8; 7] = [0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00];
const NDEF_DF_SELECT: [u8; 13] = [
    0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00,
];
const NDEF_EF_SELECT: [u8; 7] = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04];

#[derive(Debug)]
pub enum MockTransportError {}

impl core::fmt::Display for MockTransportError {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for MockTransportError {}

pub struct MockTransport {
    uid: [u8; 7],
    keys: [[u8; 16]; 5],
    key_versions: [u8; 5],
    ndef_selected: bool,
    ndef_ef_selected: bool,
    ndef: Vec<u8>,
    file_settings: Vec<u8>,
    pending_auth: Option<PendingAuth>,
    session: Option<SessionState>,
}

struct PendingAuth {
    key_no: u8,
    key: [u8; 16],
    rnd_b: [u8; 16],
}

struct SessionState {
    enc_key: [u8; 16],
    mac_key: [u8; 16],
    ti: [u8; 4],
    cmd_counter: u16,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::with_state(
            [[0u8; 16]; 5],
            [0u8; 5],
            Vec::new(),
            DEFAULT_FILE_SETTINGS.to_vec(),
        )
    }

    pub fn provisioned(
        keys: [[u8; 16]; 5],
        key_versions: [u8; 5],
        ndef: Vec<u8>,
        file_settings: Vec<u8>,
    ) -> Self {
        Self::with_state(keys, key_versions, ndef, file_settings)
    }

    fn with_state(
        keys: [[u8; 16]; 5],
        key_versions: [u8; 5],
        ndef: Vec<u8>,
        file_settings: Vec<u8>,
    ) -> Self {
        Self {
            uid: UID,
            keys,
            key_versions,
            ndef_selected: false,
            ndef_ef_selected: false,
            ndef,
            file_settings,
            pending_auth: None,
            session: None,
        }
    }

    pub fn keys(&self) -> &[[u8; 16]; 5] {
        &self.keys
    }

    pub fn key_versions(&self) -> &[u8; 5] {
        &self.key_versions
    }

    pub fn ndef(&self) -> &[u8] {
        &self.ndef
    }

    pub fn file_settings(&self) -> &[u8] {
        &self.file_settings
    }

    fn session(&self) -> &SessionState {
        self.session
            .as_ref()
            .expect("expected authenticated session")
    }

    fn session_mut(&mut self) -> &mut SessionState {
        self.session
            .as_mut()
            .expect("expected authenticated session")
    }

    fn require_ndef_selected(&self) {
        assert!(
            self.ndef_selected,
            "NDEF application must be selected first"
        );
    }

    fn response(data: Vec<u8>, sw1: u8, sw2: u8) -> Response<Vec<u8>> {
        Response { data, sw1, sw2 }
    }

    fn ok(data: Vec<u8>) -> Response<Vec<u8>> {
        Self::response(data, 0x91, 0x00)
    }

    fn iso_ok() -> Response<Vec<u8>> {
        Self::response(Vec::new(), 0x90, 0x00)
    }

    fn handle_auth_part1(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(apdu.len(), 8, "unexpected AuthenticateEV2First APDU length");
        assert_eq!(apdu[0], 0x90);
        assert_eq!(apdu[1], 0x71);
        assert_eq!(apdu[4], 0x02);
        assert_eq!(apdu[7], 0x00);

        let key_no = apdu[5] as usize;
        assert_eq!(apdu[6], 0x00, "LenCap must be zero");
        let key = self.keys[key_no];
        let rnd_b = [
            0xB9, 0xE2, 0xFC, 0x78, 0x9B, 0x64, 0xBF, 0x23, 0x7C, 0xCC, 0xAA, 0x20, 0xEC, 0x7E,
            0x6E, 0x48,
        ];
        let mut enc = rnd_b;
        aes_cbc_encrypt(&key, &[0u8; 16], &mut enc);
        self.pending_auth = Some(PendingAuth {
            key_no: key_no as u8,
            key,
            rnd_b,
        });
        Self::response(enc.to_vec(), 0x91, 0xAF)
    }

    fn handle_auth_part2(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        let pending = self
            .pending_auth
            .take()
            .expect("AuthenticateEV2First part 2 without part 1");

        assert_eq!(
            apdu.len(),
            38,
            "unexpected AuthenticateEV2First part 2 length"
        );
        assert_eq!(&apdu[..5], &[0x90, 0xAF, 0x00, 0x00, 0x20]);
        assert_eq!(apdu[37], 0x00);

        let mut ciphertext = [0u8; 32];
        ciphertext.copy_from_slice(&apdu[5..37]);
        aes_cbc_decrypt(&pending.key, &[0u8; 16], &mut ciphertext);

        let mut rnd_a = [0u8; 16];
        rnd_a.copy_from_slice(&ciphertext[..16]);

        let mut rotated_rnd_b = [0u8; 16];
        rotated_rnd_b[..15].copy_from_slice(&pending.rnd_b[1..]);
        rotated_rnd_b[15] = pending.rnd_b[0];
        assert_eq!(
            &ciphertext[16..],
            &rotated_rnd_b,
            "unexpected RndB rotation"
        );

        let mut plaintext = [0u8; 32];
        plaintext[..4].copy_from_slice(&TI);
        plaintext[4..19].copy_from_slice(&rnd_a[1..]);
        plaintext[19] = rnd_a[0];
        let mut response = plaintext;
        aes_cbc_encrypt(&pending.key, &[0u8; 16], &mut response);

        let (enc_key, mac_key) = derive_session_keys(&pending.key, &rnd_a, &pending.rnd_b);
        assert_eq!(pending.key_no, 0, "tests only authenticate with Key0");
        self.session = Some(SessionState {
            enc_key,
            mac_key,
            ti: TI,
            cmd_counter: 0,
        });

        Self::ok(response.to_vec())
    }

    fn verify_request_mac(&self, cmd: u8, header: &[u8], data: &[u8], mac: &[u8]) {
        let expected = compute_command_mac(self.session(), cmd, header, data);
        assert_eq!(
            mac,
            expected.as_slice(),
            "unexpected MAC for command 0x{cmd:02X}"
        );
    }

    fn response_with_mac(&mut self, data: &[u8]) -> Response<Vec<u8>> {
        let mac = compute_response_mac(self.session(), data);
        let mut body = data.to_vec();
        body.extend_from_slice(&mac);
        self.session_mut().cmd_counter = self.session().cmd_counter.wrapping_add(1);
        Self::ok(body)
    }

    fn update_file_settings_from_patch(&mut self, patch: &[u8]) {
        let file_type = self.file_settings[0];
        let size = [
            self.file_settings[4],
            self.file_settings[5],
            self.file_settings[6],
        ];
        let mut raw = vec![
            file_type, patch[0], patch[1], patch[2], size[0], size[1], size[2],
        ];
        raw.extend_from_slice(&patch[3..]);
        self.file_settings = raw;
    }

    fn handle_get_file_settings(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(apdu.len(), 15);
        assert_eq!(&apdu[..5], &[0x90, 0xF5, 0x00, 0x00, 0x09]);
        assert_eq!(apdu[5], 0x02, "expected NDEF file number");
        assert_eq!(apdu[14], 0x00);
        self.verify_request_mac(0xF5, &[apdu[5]], &[], &apdu[6..14]);
        let body = self.file_settings.clone();
        self.response_with_mac(&body)
    }

    fn handle_change_file_settings(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert!(apdu.len() >= 31);
        assert_eq!(apdu[0], 0x90);
        assert_eq!(apdu[1], 0x5F);
        assert_eq!(apdu[5], 0x02, "expected NDEF file number");
        assert_eq!(*apdu.last().unwrap(), 0x00);

        let body = &apdu[5..apdu.len() - 1];
        let (payload, mac) = body.split_at(body.len() - 8);
        let (header, ciphertext) = payload.split_at(1);
        self.verify_request_mac(0x5F, header, ciphertext, mac);

        let mut plaintext = ciphertext.to_vec();
        decrypt_command(self.session(), &mut plaintext);
        let patch_len = strip_m2_padding(&plaintext).expect("invalid ChangeFileSettings padding");
        self.update_file_settings_from_patch(&plaintext[..patch_len]);

        self.response_with_mac(&[])
    }

    fn handle_change_key(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(apdu[0], 0x90);
        assert_eq!(apdu[1], 0xC4);
        assert_eq!(apdu[4], 0x29);
        assert_eq!(*apdu.last().unwrap(), 0x00);

        let key_no = apdu[5] as usize;
        let ciphertext = &apdu[6..38];
        let mac = &apdu[38..46];
        self.verify_request_mac(0xC4, &[apdu[5]], ciphertext, mac);

        let mut plaintext = [0u8; 32];
        plaintext.copy_from_slice(ciphertext);
        decrypt_command(self.session(), &mut plaintext);

        if key_no == 0 {
            self.keys[0].copy_from_slice(&plaintext[..16]);
            self.key_versions[0] = plaintext[16];
            self.session_mut().cmd_counter = self.session().cmd_counter.wrapping_add(1);
            self.session = None;
            Self::ok(Vec::new())
        } else {
            let old_key = self.keys[key_no];
            let mut new_key = [0u8; 16];
            for (dst, (lhs, rhs)) in new_key
                .iter_mut()
                .zip(plaintext[..16].iter().zip(old_key.iter()))
            {
                *dst = *lhs ^ *rhs;
            }
            self.keys[key_no] = new_key;
            self.key_versions[key_no] = plaintext[16];
            self.response_with_mac(&[])
        }
    }

    fn handle_get_key_version(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(apdu.len(), 15);
        assert_eq!(&apdu[..5], &[0x90, 0x64, 0x00, 0x00, 0x09]);
        assert_eq!(apdu[14], 0x00);
        self.verify_request_mac(0x64, &[apdu[5]], &[], &apdu[6..14]);
        self.response_with_mac(&[self.key_versions[apdu[5] as usize]])
    }

    fn handle_read_data_plain(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(&apdu[..5], &[0x90, 0xAD, 0x00, 0x00, 0x07]);
        assert_eq!(*apdu.last().unwrap(), 0x00);
        assert_eq!(apdu[5], 0x02, "expected NDEF file number");

        let offset = u32::from_le_bytes([apdu[6], apdu[7], apdu[8], 0]);
        let length = u32::from_le_bytes([apdu[9], apdu[10], apdu[11], 0]);
        let start = offset as usize;
        let end = if length == 0 {
            self.ndef.len()
        } else {
            start + length as usize
        };
        let data = self.ndef[start..end.min(self.ndef.len())].to_vec();
        if self.session.is_some() {
            self.session_mut().cmd_counter = self.session().cmd_counter.wrapping_add(1);
        }
        Self::ok(data)
    }

    fn handle_write_data_plain(&mut self, apdu: &[u8]) -> Response<Vec<u8>> {
        self.require_ndef_selected();
        assert_eq!(apdu[0], 0x90);
        assert_eq!(apdu[1], 0x8D);
        assert_eq!(apdu[5], 0x02, "expected NDEF file number");
        assert_eq!(*apdu.last().unwrap(), 0x00);

        let offset = u32::from_le_bytes([apdu[6], apdu[7], apdu[8], 0]) as usize;
        let len = u32::from_le_bytes([apdu[9], apdu[10], apdu[11], 0]) as usize;
        let data = &apdu[12..12 + len];
        if self.ndef.len() < offset + len {
            self.ndef.resize(offset + len, 0);
        }
        self.ndef[offset..offset + len].copy_from_slice(data);
        if self.session.is_some() {
            self.session_mut().cmd_counter = self.session().cmd_counter.wrapping_add(1);
        }
        Self::ok(Vec::new())
    }
}

impl Transport for MockTransport {
    type Error = MockTransportError;
    type Data = Vec<u8>;

    async fn transmit(&mut self, apdu: &[u8]) -> Result<Response<Self::Data>, Self::Error> {
        let response = match apdu {
            apdu if apdu == NDEF_DF_SELECT => {
                self.ndef_selected = true;
                self.ndef_ef_selected = false;
                Self::iso_ok()
            }
            apdu if apdu == NDEF_EF_SELECT => {
                self.require_ndef_selected();
                self.ndef_ef_selected = true;
                Self::iso_ok()
            }
            [0x00, 0xD6, ..] => {
                self.require_ndef_selected();
                assert!(
                    self.ndef_ef_selected,
                    "NDEF EF must be selected before ISOUpdateBinary"
                );
                let data = apdu[5..].to_vec();
                self.ndef = data;
                Self::iso_ok()
            }
            [0x90, 0x71, ..] => self.handle_auth_part1(apdu),
            [0x90, 0xAF, ..] if self.pending_auth.is_some() => self.handle_auth_part2(apdu),
            [0x90, 0xF5, ..] => self.handle_get_file_settings(apdu),
            [0x90, 0x5F, ..] => self.handle_change_file_settings(apdu),
            [0x90, 0xC4, ..] => self.handle_change_key(apdu),
            [0x90, 0x64, ..] => self.handle_get_key_version(apdu),
            [0x90, 0xAD, ..] => self.handle_read_data_plain(apdu),
            [0x90, 0x8D, ..] => self.handle_write_data_plain(apdu),
            _ => panic!("unexpected APDU: {:02X?}", apdu),
        };

        Ok(response)
    }

    async fn get_uid(&mut self) -> Result<Self::Data, Self::Error> {
        Ok(self.uid.to_vec())
    }
}

pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("mock tests must not block"),
    }
}

fn derive_session_keys(key: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let sv1 = session_vector_aes([0xA5, 0x5A], rnd_a, rnd_b);
    let sv2 = session_vector_aes([0x5A, 0xA5], rnd_a, rnd_b);
    (cmac_aes(key, &sv1), cmac_aes(key, &sv2))
}

fn session_vector_aes(label: [u8; 2], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 32] {
    let mut sv = [0u8; 32];
    sv[0..2].copy_from_slice(&label);
    sv[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    sv[6..8].copy_from_slice(&rnd_a[0..2]);
    for i in 0..6 {
        sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i];
    }
    sv[14..24].copy_from_slice(&rnd_b[6..16]);
    sv[24..32].copy_from_slice(&rnd_a[8..16]);
    sv
}

fn cmac_aes(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("16-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn truncate_mac(full: &[u8; 16]) -> [u8; 8] {
    core::array::from_fn(|i| full[2 * i + 1])
}

fn compute_command_mac(session: &SessionState, cmd: u8, header: &[u8], data: &[u8]) -> [u8; 8] {
    let mut input = Vec::with_capacity(1 + 2 + 4 + header.len() + data.len());
    input.push(cmd);
    input.extend_from_slice(&session.cmd_counter.to_le_bytes());
    input.extend_from_slice(&session.ti);
    input.extend_from_slice(header);
    input.extend_from_slice(data);
    truncate_mac(&cmac_aes(&session.mac_key, &input))
}

fn compute_response_mac(session: &SessionState, data: &[u8]) -> [u8; 8] {
    let mut input = Vec::with_capacity(1 + 2 + 4 + data.len());
    input.push(0x00);
    input.extend_from_slice(&session.cmd_counter.wrapping_add(1).to_le_bytes());
    input.extend_from_slice(&session.ti);
    input.extend_from_slice(data);
    truncate_mac(&cmac_aes(&session.mac_key, &input))
}

fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    assert!(!buf.is_empty() && buf.len().is_multiple_of(16));
    let cipher = Aes128::new(&Array::from(*key));
    let mut prev = *iv;
    for chunk in buf.chunks_exact_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut out = [0u8; 16];
        cipher.encrypt_block_b2b(&Array::from(block), (&mut out).into());
        chunk.copy_from_slice(&out);
        prev = out;
    }
}

fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    assert!(!buf.is_empty() && buf.len().is_multiple_of(16));
    let cipher = Aes128::new(&Array::from(*key));
    let mut prev = *iv;
    for chunk in buf.chunks_exact_mut(16) {
        let mut saved = [0u8; 16];
        saved.copy_from_slice(chunk);
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut out = [0u8; 16];
        cipher.decrypt_block_b2b(&Array::from(block), (&mut out).into());
        chunk.copy_from_slice(&out);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev = saved;
    }
}

fn command_iv(enc_key: &[u8; 16], ti: &[u8; 4], cmd_counter: u16) -> [u8; 16] {
    let mut input = [0u8; 16];
    input[0..2].copy_from_slice(&[0xA5, 0x5A]);
    input[2..6].copy_from_slice(ti);
    input[6..8].copy_from_slice(&cmd_counter.to_le_bytes());
    let cipher = Aes128::new(&Array::from(*enc_key));
    let mut out = [0u8; 16];
    cipher.encrypt_block_b2b(&Array::from(input), (&mut out).into());
    out
}

fn decrypt_command(session: &SessionState, buf: &mut [u8]) {
    let iv = command_iv(&session.enc_key, &session.ti, session.cmd_counter);
    aes_cbc_decrypt(&session.enc_key, &iv, buf);
}

fn strip_m2_padding(buf: &[u8]) -> Option<usize> {
    let mut i = buf.len();
    while i > 0 && buf[i - 1] == 0x00 {
        i -= 1;
    }
    if i == 0 || buf[i - 1] != 0x80 {
        return None;
    }
    Some(i - 1)
}

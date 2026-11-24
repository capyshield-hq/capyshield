//! Local root CA and on-the-fly leaf certificates for MITM inspection.

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicU64, Ordering};
use time::{Duration, OffsetDateTime};

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub cert_pem: String,
    pub key_pem: String,
    pub(crate) cert_der: CertificateDer<'static>,
    /// One key for every leaf: generating a key per host is the slow part of MITM.
    leaf_key: KeyPair,
    serial: AtomicU64,
}

impl Ca {
    pub fn generate() -> Result<Ca, rcgen::Error> {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "CapyShield Local Root CA");
        p.distinguished_name
            .push(DnType::OrganizationName, "CapyShield (local, never shared)");
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(5 * 365);
        let cert = p.self_signed(&key)?;
        Ca::from_parts(cert.pem(), key)
    }

    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Ca, rcgen::Error> {
        Ca::from_parts(cert_pem.to_string(), KeyPair::from_pem(key_pem)?)
    }

    fn from_parts(cert_pem: String, key: KeyPair) -> Result<Ca, rcgen::Error> {
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|_| rcgen::Error::CouldNotParseCertificate)?;
        Ok(Ca {
            key_pem: key.serialize_pem(),
            issuer: Issuer::from_ca_cert_pem(&cert_pem, key)?,
            cert_pem,
            cert_der,
            leaf_key: KeyPair::generate()?,
            serial: AtomicU64::new(OffsetDateTime::now_utc().unix_timestamp_nanos() as u64),
        })
    }

    pub(crate) fn leaf(&self, host: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), rcgen::Error> {
        let mut p = CertificateParams::new(vec![host.to_string()])?;
        p.distinguished_name.push(DnType::CommonName, host);
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(30);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        // Leaves share a key, so the default (pubkey-hash) serial would collide across hosts.
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        p.serial_number = Some(SerialNumber::from_slice(&[&[0x01], &serial.to_be_bytes()[..]].concat()));
        let cert = p.signed_by(&self.leaf_key, &self.issuer)?;
        Ok((cert.der().clone(), PrivateKeyDer::Pkcs8(self.leaf_key.serialize_der().into())))
    }
}

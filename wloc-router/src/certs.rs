use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa};

use crate::config::HOSTS;

pub async fn generate(out_dir: &Path) -> Result<()> {
    let cert_dir = out_dir.join("certs");
    tokio::fs::create_dir_all(&cert_dir).await?;

    let mut ca_params = CertificateParams::new(vec!["WLOC Router Local CA".to_string()]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = dn("WLOC Router Local CA");
    let ca_cert = Certificate::from_params(ca_params)?;

    let mut leaf_params =
        CertificateParams::new(HOSTS.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    leaf_params.distinguished_name = dn("WLOC Router Apple Location MITM");
    let leaf_cert = Certificate::from_params(leaf_params)?;

    let ca_pem = ca_cert.serialize_pem()?;
    let ca_key_pem = ca_cert.serialize_private_key_pem();
    let server_pem = leaf_cert.serialize_pem_with_signer(&ca_cert)?;
    let server_key_pem = leaf_cert.serialize_private_key_pem();

    write(cert_dir.join("ca.pem"), ca_pem).await?;
    write(cert_dir.join("ca-key.pem"), ca_key_pem).await?;
    write(cert_dir.join("server.pem"), server_pem).await?;
    write(cert_dir.join("server-key.pem"), server_key_pem).await?;

    println!("generated certs in {}", cert_dir.display());
    println!("install and fully trust {}", cert_dir.join("ca.pem").display());
    Ok(())
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

async fn write(path: impl AsRef<Path>, data: String) -> Result<()> {
    let path = path.as_ref();
    tokio::fs::write(path, data)
        .await
        .with_context(|| format!("write {}", path.display()))
}

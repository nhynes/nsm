#![deny(rust_2018_idioms, unreachable_pub)]
#![forbid(unsafe_code)]

use aws_nitro_enclaves_cose::{error::COSEError, COSESign1};
use nsm_io::{ErrorCode, Request, Response};
use openssl::{ec::EcKeyRef, pkey::Public};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub struct Nsm {
    fd: i32,
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_driver::nsm_exit(self.fd)
    }
}

impl Nsm {
    pub fn connect() -> Self {
        Self {
            fd: nsm_driver::nsm_init(),
        }
    }

    /// Returns up to 256 bytes of entropy.
    fn get_random(&self) -> Result<Vec<u8>, Error> {
        match self.process_request(Request::GetRandom)? {
            Response::GetRandom { random } => Ok(random),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn generate_attestation(&self, params: AttestationParams) -> Result<AttestationDoc, Error> {
        let res = self.process_request(Request::Attestation {
            user_data: params.user_data.map(ByteBuf::from),
            nonce: params.nonce.map(ByteBuf::from),
            public_key: params.public_key.map(ByteBuf::from),
        })?;
        match res {
            Response::Attestation { document } => Ok(AttestationDoc(document)),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn describe(&self) -> Result<Description, Error> {
        match self.process_request(Request::DescribeNSM)? {
            Response::DescribeNSM {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            } => Ok(Description {
                version: Version::new(
                    version_major as u64,
                    version_minor as u64,
                    version_patch as u64,
                ),
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            }),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Reqds the  Platform Configuration Register at the specified index.
    pub fn get_pcr(&mut self, index: u16) -> Result<Pcr, Error> {
        match self.process_request(Request::DescribePCR { index })? {
            Response::DescribePCR { lock, data } => Ok(Pcr {
                index,
                locked: lock,
                data,
            }),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Extends the Platform Configuration Registers at the specified index.
    /// Returns the updated data.
    pub fn extend_pcr(&self, index: u16, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.process_request(Request::ExtendPCR { index, data })? {
            Response::ExtendPCR { data } => Ok(data),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Locks the Platform Configuration Registers at the specified index.
    pub fn lock_pcr(&self, index: u16) -> Result<(), Error> {
        match self.process_request(Request::LockPCR { index })? {
            Response::LockPCR => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Locks the Platform Configuration Registers with indices less than the provided one.
    pub fn lock_pcrs_below(&self, index: u16) -> Result<(), Error> {
        match self.process_request(Request::LockPCRs { range: index })? {
            Response::LockPCRs => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }

    fn process_request(&self, request: Request) -> Result<Response, Error> {
        match nsm_driver::nsm_process_request(self.fd, request) {
            Response::Error(code) => Err(code.into()),
            res => Ok(res),
        }
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Description {
    /// The Nitro Secure Module version.
    pub version: Version,

    /// An identifier for a singular Nitro Secure Module.
    pub module_id: String,

    // The maximum number of Platform Configuration Registers exposed by the Nitro Secure Module.
    pub max_pcrs: u16,

    /// The indicies of the Platform Configuration Registers that are read-only.
    pub locked_pcrs: std::collections::BTreeSet<u16>,

    /// The digest of the Platform Configuration Register bank.
    pub digest: nsm_io::Digest,
}

#[derive(Clone, Debug)]
pub struct Pcr {
    index: u16,
    locked: bool,
    data: Vec<u8>,
}

impl Pcr {
    /// Returns the index of this Platform Configuration Register.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Returns whether this Platform Configuration Register has been locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns the data stored by this Platform Configuration Register.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationParams {
    /// Includes additional user data in the (signed) Attestation Doc.
    user_data: Option<Vec<u8>>,

    /// Includes an additional nonce in the (signed) Attestation Doc, which
    /// can be used to establish attestation freshness.
    nonce: Option<Vec<u8>>,

    /// Includes a user-provided public key in the Attestation Doc. The private key
    /// should be known to the enclave and used to decrypt messages sent by other services.
    public_key: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttestationDoc(#[serde(with = "serde_bytes")] Vec<u8>);

impl AttestationDoc {
    /// Authenticates the attestation doc and extracts the payload.
    pub fn decode(
        self,
        public_key: &EcKeyRef<Public>,
    ) -> Result<nsm_io::AttestationDoc, COSEError> {
        let payload =
            COSESign1::from_bytes(&self.0).and_then(|c| c.get_payload(Some(public_key)))?;
        serde_cbor::from_slice(&payload).map_err(COSEError::SerializationError)
    }

    /// Extracts the attestation doc without validating the signature.
    pub fn dangerous_insecure_decode(self) -> Result<nsm_io::AttestationDoc, COSEError> {
        let payload = COSESign1::from_bytes(&self.0).and_then(|c| c.get_payload(None))?;
        serde_cbor::from_slice(&payload).map_err(COSEError::SerializationError)
    }
}

impl rand_core::block::BlockRngCore for Nsm {
    type Item = u8;
    type Results = Vec<Self::Item>;

    fn generate(&mut self, results: &mut Self::Results) {
        *results = self.get_random().unwrap()
    }
}

impl rand_core::CryptoRng for Nsm {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input argument(s) invalid")]
    InvalidArgument,

    #[error("Platform Configuration Register index out of bounds")]
    InvalidIndex,

    #[error("the received response does not correspond to the earlier request")]
    InvalidResponse,

    #[error("Platform Configuration Register is in read-only mode and the operation attempted to modify it")]
    ReadOnlyIndex,

    #[error("given request cannot be fulfilled due to missing capabilities")]
    InvalidOperation,

    #[error("operation succeeded but provided output buffer is too small")]
    BufferTooSmall,

    #[error("the user-provided input is too large")]
    InputTooLarge,

    #[error("Nitro Secure Module cannot fulfill request due to internal errors")]
    InternalError,
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::Success => unreachable!("ErrorCode::Success is not an Error"),
            ErrorCode::InvalidArgument => Error::InvalidArgument,
            ErrorCode::InvalidIndex => Error::InvalidIndex,
            ErrorCode::InvalidResponse => Error::InvalidResponse,
            ErrorCode::ReadOnlyIndex => Error::ReadOnlyIndex,
            ErrorCode::InvalidOperation => Error::InvalidOperation,
            ErrorCode::BufferTooSmall => Error::BufferTooSmall,
            ErrorCode::InputTooLarge => Error::InputTooLarge,
            ErrorCode::InternalError => Error::InternalError,
        }
    }
}

#[cfg(windows)] extern crate winapi;
extern crate log;
#[macro_use(defer)] extern crate scopeguard;
extern crate simple_logger;

use clap::Clap;
use log::{Level, debug, error};
use std::convert::TryFrom;
use std::ffi::CString;
use std::mem::{size_of};
use std::ptr::null_mut;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::wincrypt::{
	CERT_CLOSE_STORE_CHECK_FLAG,
	CERT_NAME_SIMPLE_DISPLAY_TYPE,  
	CERT_STORE_PROV_SYSTEM,
	CERT_SYSTEM_STORE_CURRENT_USER,
	CRYPT_SILENT,
	HCERTSTORE,
	HCRYPTPROV,
	PCCERT_CONTEXT,
	PP_SIGNATURE_PIN, 
	PROV_RSA_FULL, 
	CertCloseStore, 
	CertEnumCertificatesInStore, 
	CertGetNameStringA, 
	CertOpenStore, 
	CryptAcquireContextA, 
	CryptReleaseContext, 
	CryptSetProvParam,
	szOID_NIST_sha256
};
mod cryptuiapi;
use cryptuiapi::{
	CERTIFICATE_INFO_U,
	CRYPTUI_WIZ_DIGITAL_SIGN_CERT,
	CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE,
	CRYPTUI_WIZ_DIGITAL_SIGN_INFO,
	CRYPTUI_WIZ_NO_UI,
	FILE_INFO_U,
	CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO,
	PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO,
	CryptUIWizDigitalSign
};

use std::ffi::{OsStr, OsString};
use std::os::windows::prelude::*;
pub trait ToWide {
    fn to_wide(&self) -> Vec<u16>;
    fn to_wide_null(&self) -> Vec<u16>;
}
impl<T> ToWide for T where T: AsRef<OsStr> {
    fn to_wide(&self) -> Vec<u16> {
        self.as_ref().encode_wide().collect()
    }
    fn to_wide_null(&self) -> Vec<u16> {
        self.as_ref().encode_wide().chain(Some(0)).collect()
    }
}
pub trait FromWide where Self: Sized {
    fn from_wide_null(wide: &[u16]) -> Self;
}
impl FromWide for OsString {
    fn from_wide_null(wide: &[u16]) -> OsString {
        let len = wide.iter().take_while(|&&c| c != 0).count();
        OsString::from_wide(&wide[..len])
    }
}

/// Command line options setup
#[derive(Clap)]
#[clap(version = "0.1.0", author = "Scott Sedgwick <ssedgwick@cochlear.com>")]
struct Opts {
    #[clap(short, long, default_value = "Cochlear Limited")]
    certificate: String,
    #[clap(short, long, default_value = "L!ghtn!ngMcQu33n")]
    pin: String,
    #[clap(short, long, default_value = "http://timestamp.digicert.com")]
    timestamp: String,
    #[clap(short, long, default_value = "CustomSound.exe")]
    filename: String,
    #[clap(short, long)]
    debug: bool
}

/// Wrapper around the CryptAcquireContextA function
fn get_crypto_context() -> Result<HCRYPTPROV, String> {
	debug!("Getting crypto context");
	let ph_prov = null_mut();
    let token_name: CString = CString::new("\\\\.\\AKS ifdh 0").unwrap();
    let etoken_base_crypt_prov_name: CString = CString::new("eToken Base Cryptographic Provider").unwrap();
	let context_ok: BOOL;
	unsafe{
		context_ok = CryptAcquireContextA(ph_prov, token_name.as_ptr(), etoken_base_crypt_prov_name.as_ptr(), PROV_RSA_FULL, CRYPT_SILENT);
	}
	if context_ok == FALSE {
		let e: DWORD;
		unsafe {
			e = GetLastError();
		}
		Err(format!("CryptAcquireContext failed, error {:#x}", e))
	} else {
		let result: HCRYPTPROV;
		unsafe {
			result = *ph_prov;
		}
		Ok(result)
	}
}

/// Wrapper around the CryptSetProvParam function, specialized for the PP_SIGNATURE_PIN parameter
fn set_token_pin(ph_prov: HCRYPTPROV, pin: String) -> Result<(), String> {
	debug!("Setting token PIN");
	let bpin = CString::new(pin).unwrap().as_bytes().as_ptr();
	let set_pin_ok: BOOL;
	unsafe {
		set_pin_ok = CryptSetProvParam(ph_prov, PP_SIGNATURE_PIN, bpin, 0);
	}
	if set_pin_ok == FALSE {
		let e: DWORD;
		unsafe {
			e = GetLastError();
		}
		Err(format!("CryptSetProvParam failed, error {:#x}", e))
	} else {
		Ok(())
	}
}

/// Wrapper around the CertOpenStore function
fn open_cert_store() -> Result<HCERTSTORE, String> {
	debug!("Opening certificate store");
	let null_store: HCERTSTORE = null_mut();
	let store_para: CString = CString::new("MY").unwrap();
	let cert_store: HCERTSTORE;
	unsafe {
		cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, store_para.as_ptr() as *mut _);
	}
	if cert_store == null_store {
		Err("Could not open the MY system store".to_string())
	} else {
		Ok(cert_store)
	}
}

fn find_certificate(h_system_store: HCERTSTORE, desired_cert_name: String) -> Result<PCCERT_CONTEXT, String> {
	let mut done = false;
	let mut result: Result<PCCERT_CONTEXT, String> = Err("No matching certificate to sign found".to_string());
	let desired_cert: PCCERT_CONTEXT = null_mut();
	let desired_cert_name_os = OsString::from(desired_cert_name);
	while !done {
		unsafe {
			let desired_cert = CertEnumCertificatesInStore(h_system_store, desired_cert);
			let cb_size = CertGetNameStringA(desired_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null_mut(), null_mut(), 0);
			if cb_size > 0 {
				let mut buf = [0; 0x200];
				let mut bufu = [0 as u16; 0x200];
				let cb_size = CertGetNameStringA(desired_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null_mut(), buf.as_mut_ptr(), cb_size);
				if cb_size > 0 {
					for x in 0..buf.len() - 1 {
						bufu[x] = u16::try_from(buf[x]).unwrap();
					}
					let cert_name = OsString::from_wide_null(&bufu);
					if cert_name == desired_cert_name_os {
						result = Ok(desired_cert);
						done = true;
					}
				}
			} else {
				done = true;
			}
		}
	}
	return result;
}

// let user1 = User {
// 	email: String::from("someone@example.com"),
// 	username: String::from("someusername123"),
// 	active: true,
// 	sign_in_count: 1,
// };

fn sign_using_cert(cert: PCCERT_CONTEXT, timestamp_url: String, filename: String) -> Result<(), String> {
	let mut result: Result<(), String> = Err("FATAL ERROR".to_string()); 
	let sign_ext_info = CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO {
		dw_size: u32::try_from(size_of::<CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO>()).unwrap(),
		dw_attr_flags: 0,
		pwsz_description: null_mut(),
		pwsz_more_info_location: null_mut(),
		psz_hash_alg: CString::new(szOID_NIST_sha256).unwrap().as_ptr(),
		pwsz_signing_cert_display_string: null_mut(),
		h_additional_cert_store: null_mut(),
		ps_authenticated: null_mut(),
		ps_unauthenticated: null_mut(),
	};
	let file_info : FILE_INFO_U;
	unsafe {
		file_info = std::mem::zeroed();
	}
	// let file_name = file_info.pwsz_file_name_mut();
	// file_name = CString::new(filename).unwrap().as_bytes_with_nul();
	let cert_info : CERTIFICATE_INFO_U;
	unsafe {
		cert_info = std::mem::zeroed();
	}
	// let cert_name = cert_info.p_signing_cert_context_mut();
	// cert_name = cert;
	let digital_sign_info = CRYPTUI_WIZ_DIGITAL_SIGN_INFO {
		dw_size: u32::try_from(size_of::<CRYPTUI_WIZ_DIGITAL_SIGN_INFO>()).unwrap(),
		dw_subject_choice: CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE,
		u_file_info: file_info,
		dw_signing_cert_choice: CRYPTUI_WIZ_DIGITAL_SIGN_CERT,
		u_certificate_info: cert_info,
		pwsz_timestamp_url: null_mut(), //CString::new(timestamp_url).unwrap().as_ptr(),
		dw_additional_cert_choice: 0,
		p_sign_ext_info: sign_ext_info,
	};
	let p_digital_sign_info: PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO = &digital_sign_info;
	unsafe {
		let res = CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, null_mut(), null_mut(), p_digital_sign_info, null_mut());
		if res == FALSE {
			result = Err("CryptUIWizDigitalSign failed, error ".to_string());
		} else {
			result = Ok(());
		}
	}
	return result;
}

/// Top level signing function
fn sign(opts: Opts) -> Result<(), String> {
	let ph_prov = get_crypto_context()?;
	// Ensure the crypto context is released
	defer! {
		debug!("Releasing crypto context");
		unsafe {
			CryptReleaseContext(ph_prov, 0);
		}
	};
	
	set_token_pin(ph_prov, opts.pin.clone())?;

	let h_system_store = open_cert_store()?;
	// Ensure the certificate store is closed
	defer! {
		debug!("Closing certificate store");
		unsafe {
			CertCloseStore(h_system_store, CERT_CLOSE_STORE_CHECK_FLAG);
		}
	};

	// Iterate over certificates in store and locate the named certificate
	let cert = find_certificate(h_system_store, "".to_string())?;

	// Sign the specified file using the named certificate
	sign_using_cert(cert, opts.timestamp.clone(), opts.filename.clone())
}

fn main() {
	// Parse the command line options
 	let opts: Opts = Opts::parse();

    // Set up logging
	if opts.debug {
    	simple_logger::init_with_level(Level::Debug).unwrap();
	} else {
    	simple_logger::init_with_level(Level::Error).unwrap();
	}

	// Log inputs
    debug!("Certificate Name: {}", opts.certificate);
    debug!("Certificate PIN : {}", opts.pin);
    debug!("Timestamp Server: {}", opts.timestamp);
    debug!("Filename to sign: {}", opts.filename);

	// Perform signing operation
	match sign(opts) {
		Ok(()) => println!("Done!"),
		Err(s) => error!("{}", s)
	}
}

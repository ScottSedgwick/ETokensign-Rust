#[cfg(windows)] extern crate winapi;
extern crate log;
#[macro_use(defer)] extern crate scopeguard;
extern crate simple_logger;

use clap::Clap;
use log::Level;
use std::ffi::CString;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::wincrypt::{
	CERT_CLOSE_STORE_CHECK_FLAG, 
	CERT_STORE_PROV_SYSTEM,
	CERT_SYSTEM_STORE_CURRENT_USER,
	CRYPT_SILENT,
	HCERTSTORE,
	HCRYPTPROV,
	PP_SIGNATURE_PIN, 
	PROV_RSA_FULL, 
	CertCloseStore, 
	CertOpenStore, 
	CryptAcquireContextA, 
	CryptReleaseContext, 
	CryptSetProvParam
};

// Set up command line options
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

fn get_crypto_context() -> Result<HCRYPTPROV, String> {
	log::debug!("Getting crypto context");
	let ph_prov = std::ptr::null_mut();
    let token_name: std::ffi::CString = CString::new("\\\\.\\AKS ifdh 0").unwrap();
    let etoken_base_crypt_prov_name: std::ffi::CString = CString::new("eToken Base Cryptographic Provider").unwrap();
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

fn set_token_pin(ph_prov: HCRYPTPROV, opts: Opts) -> Result<(), String> {
	log::debug!("Setting token PIN");
	let bpin = CString::new(opts.pin.clone()).unwrap().as_bytes().as_ptr();
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

fn open_cert_store() -> Result<HCERTSTORE, String> {
	log::debug!("Opening certificate store");
	let null_store: HCERTSTORE = std::ptr::null_mut();
	let store_para: std::ffi::CString = CString::new("MY").unwrap();
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

fn close_cert_store(cert_store: HCERTSTORE)  {
	log::debug!("Closing certificate store");
	unsafe {
		CertCloseStore(cert_store, CERT_CLOSE_STORE_CHECK_FLAG);
	}
}

fn release_crypto_context(ph_prov: HCRYPTPROV) {
	log::debug!("Releasing crypto context");
	unsafe {
		CryptReleaseContext(ph_prov, 0);
	}
}

fn sign(opts: Opts) -> Result<(), String> {
	let ph_prov = get_crypto_context()?;
	defer! {
		release_crypto_context(ph_prov);
	};
	
	set_token_pin(ph_prov, opts)?;
	let h_system_store = open_cert_store()?;
	defer! {
		close_cert_store(h_system_store);
	};
	
	Ok(())
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
    log::debug!("Certificate Name: {}", opts.certificate);
    log::debug!("Certificate PIN : {}", opts.pin);
    log::debug!("Timestamp Server: {}", opts.timestamp);
    log::debug!("Filename to sign: {}", opts.filename);

	// Perform signing operation
	match sign(opts) {
		Ok(()) => println!("Done!"),
		Err(s) => log::error!("{}", s)
	}
}

use winapi::shared::guiddef::{GUID};
use winapi::shared::minwindef::{BOOL, BYTE, DWORD};
use winapi::um::wincrypt::{HCERTSTORE, PCCERT_CONTEXT, PCRYPT_ATTRIBUTES};
use winapi::um::winnt::{HANDLE, LPCSTR, LPCWSTR, LPWSTR};

#[macro_use]
mod macros;

pub type CryptUiWizDigitalSignFlag = DWORD;
pub const CRYPTUI_WIZ_UI: CryptUiWizDigitalSignFlag = 0x0000;
pub const CRYPTUI_WIZ_NO_UI: CryptUiWizDigitalSignFlag = 0x0001;

STRUCT!{struct CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO {
    dw_size: DWORD,
    p_guid_subject: *mut GUID,
    cb_blob: DWORD,
    pb_blob: *mut BYTE,
    pwsz_display_name: LPCWSTR,
}}
pub type PCRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO = *mut CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO;

UNION!{union FILE_INFO_U {
    [usize; 1],
    pwsz_file_name pwsz_file_name_mut: LPCWSTR,
    p_sign_blob_info p_sign_blob_info_mut: PCRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO,
}}

type PFNCFILTERPROC = DWORD;
STRUCT!{struct PCCRYPTUI_WIZ_DIGITAL_SIGN_STORE_INFO {
    dw_size: DWORD,
    c_cert_store: DWORD,
    rgh_cert_store: *mut HCERTSTORE,
    p_filter_callback: PFNCFILTERPROC,
    pv_callback_data: *mut DWORD,
}}

STRUCT!{struct PCCRYPTUI_WIZ_DIGITAL_SIGN_PVK_FILE_INFO {
    dw_size: DWORD,
    pwsz_pvk_file_name: LPWSTR, 
    pwsz_prov_name: LPWSTR,
    dw_prov_type: DWORD,
}}

STRUCT!{struct PCRYPT_KEY_PROV_PARAM {
    dw_param: DWORD,
    pb_data: *mut BYTE,
    cb_data: DWORD,
    dw_flags: DWORD,
}}

STRUCT!{struct PCRYPT_KEY_PROV_INFO {
    pwsz_container_name: LPWSTR,
    pwsz_prov_name: LPWSTR,
    dw_prov_type: DWORD,
    dw_flags: DWORD,
    c_prov_param: DWORD,
    rg_prov_param: PCRYPT_KEY_PROV_PARAM,
    dw_key_spec: DWORD,
}}

UNION!{ union PROVIDER_INFO_U {
    [usize; 2],
    p_pvk_file_info p_pvk_file_info_mut: PCCRYPTUI_WIZ_DIGITAL_SIGN_PVK_FILE_INFO,
    p_pvk_prov_info p_pvk_prov_info_mut: PCRYPT_KEY_PROV_INFO,
}}
  
STRUCT!{struct PCCRYPTUI_WIZ_DIGITAL_SIGN_CERT_PVK_INFO {
    dw_size: DWORD,
    pwsz_signing_cert_file_name: LPWSTR,
    dw_pvk_choice: DWORD,
    provider_info_u: PROVIDER_INFO_U,
}}

UNION!{union CERTIFICATE_INFO_U {
    [usize; 2],
    p_signing_cert_context p_signing_cert_context_mut: PCCERT_CONTEXT,
    p_signing_cert_store p_signing_cert_store_mut: PCCRYPTUI_WIZ_DIGITAL_SIGN_STORE_INFO,
    p_signing_cert_pvk_info p_signing_cert_pvk_info_mut: PCCRYPTUI_WIZ_DIGITAL_SIGN_CERT_PVK_INFO,
}}

STRUCT!{struct CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO {
    dw_size: DWORD,
    dw_attr_flags: DWORD,
    pwsz_description: LPCWSTR,
    pwsz_more_info_location: LPCWSTR,
    psz_hash_alg: LPCSTR,
    pwsz_signing_cert_display_string: LPCWSTR,
    h_additional_cert_store: HCERTSTORE,
    ps_authenticated: PCRYPT_ATTRIBUTES,
    ps_unauthenticated: PCRYPT_ATTRIBUTES,
}}

pub type SigningSubjectChoice = DWORD;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_MY: SigningSubjectChoice = 0;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_CERT: SigningSubjectChoice = 1;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_STORE: SigningSubjectChoice = 2;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_PVK: SigningSubjectChoice = 3;

pub type SigningCertChoice = DWORD;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_PROMPT: SigningCertChoice = 0;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE: SigningCertChoice = 1;
pub const CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_BLOB: SigningCertChoice = 2;

STRUCT!{struct CRYPTUI_WIZ_DIGITAL_SIGN_INFO {
    dw_size: DWORD,
    dw_subject_choice: SigningSubjectChoice,
    u_file_info: FILE_INFO_U,
    dw_signing_cert_choice: SigningCertChoice,
    u_certificate_info: CERTIFICATE_INFO_U,
    pwsz_timestamp_url: LPCWSTR,
    dw_additional_cert_choice: DWORD,
    p_sign_ext_info: CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO,
}}
pub type PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO = *mut CRYPTUI_WIZ_DIGITAL_SIGN_INFO;

STRUCT!{struct CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT {
    dw_size: DWORD,
    cb_blob: DWORD,
    pb_blob: *mut BYTE,
}}
pub type PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT = *mut CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT;

extern "system" {
    pub fn CryptUIWizDigitalSign(
        dw_flags: CryptUiWizDigitalSignFlag,
        hwnd_parent: HANDLE,
        pwsz_wizard_title: LPCWSTR,
        p_digital_sign_info: PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO,
        pp_sign_context: *mut PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT,
    ) -> BOOL;
}
use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use winapi::ctypes::{c_char, wchar_t};
use windows_dll::dll;

#[derive(Debug)]
pub enum PidGenResult {
    Ok,
    PKeyMissing,
    InvalidArguments,
    InvalidKey,
    BlackListedKey,
    UnknownError(u32)
}

#[repr(C)]
#[derive(Default, Debug)]
struct DigitalProductId {
    size: u32,
    major_version: u16,
    minor_version: u16,
    product_id: [c_char; 24],
    key_index: u32,
    edition_id: [c_char; 16],
    cd_key: [c_char; 16],
    clone_status: u32,
    time: u32,
    random: u32,
    lt: u32,
    license_data: [u32; 2],
    oem_id: [c_char; 8],
    bundle_id: u32,
    hardware_id_static: [u8; 8],
    hardware_id_type_static: u32,
    bios_checksum_static: u32,
    vol_ser_static: u32,
    total_ram_static: u32,
    video_bios_checksum_static: u32,
    hardware_id_dynamic: [u8; 8],
    hardware_id_type_dynamic: u32,
    bios_checksum_dynamic: u32,
    vol_ser_dynamic: u32,
    total_ram_dynamic: u32,
    video_bios_checksum_dynamic: u32,
    crc32: u32
}


#[repr(C)]
#[derive(Debug)]
struct DigitalProductId4 {
    size: u32,
    major_version: u16,
    minor_version: u16,
    advanced_pid: [wchar_t; 64],
    activation_id: [wchar_t; 64],
    oem_id: [wchar_t; 8],
    edition_type: [wchar_t; 260],
    is_upgrade: bool,
    reserved: [u8; 7],
    cd_key: [u8; 16],
    cd_ley_256_hash: [u8; 32],
    b_256_hash: [u8; 32],
    edition_id: [wchar_t; 64],
    key_type: [wchar_t; 64],
    eula: [wchar_t; 64]
}

impl Default for DigitalProductId4 {
    fn default() -> Self {
        DigitalProductId4 {
            size: 0,
            major_version: 0,
            minor_version: 0,
            advanced_pid: [0; 64],
            activation_id: [0; 64],
            oem_id: [0; 8],
            edition_type: [0; 260],
            is_upgrade: false,
            reserved: [0; 7],
            cd_key: [0; 16],
            cd_ley_256_hash: [0; 32],
            b_256_hash: [0; 32],
            edition_id: [0; 64],
            key_type: [0; 64],
            eula: [0; 64],
        }
    }
}

#[dll(pidgenx)]
extern "system" {
    #[link_name = "PidGenX"]
    fn pid_gen_x(product_key: *const wchar_t, config_file_path: *const wchar_t, mpc: *const wchar_t, oem_id: *const wchar_t, product_id: *mut wchar_t, id: *mut DigitalProductId, id4: *mut DigitalProductId4) -> u32;
}

pub fn validate_key(key: &str, mpc: &str, config: &str) -> PidGenResult {
    unsafe {
        let mut product_id: [wchar_t; 24] = [0; 24];
        let mut id = DigitalProductId::default();
        let mut id4 = DigitalProductId4::default();
        id.size = size_of::<DigitalProductId>() as u32;
        id4.size = size_of::<DigitalProductId4>() as u32;

        let mut key: Vec<u16> = OsString::from(key).encode_wide().collect();
        let mut config: Vec<u16> = OsString::from(config).encode_wide().collect();
        let mut mpc: Vec<u16> = OsString::from(mpc).encode_wide().collect();

        // null terminate the strings
        key.push(0);
        config.push(0);
        mpc.push(0);

        //println!("key = {key:?}");

        let result = pid_gen_x(key.as_ptr(),config.as_ptr(), mpc.as_ptr(), null(), &mut product_id[0] as *mut _, &mut id, &mut id4 as *mut _);

        //println!("id = {id:?}");
        //println!("id4 = {id4:?}");

        match result {
            0 => PidGenResult::Ok,
            0x80070002 => PidGenResult::PKeyMissing,
            0x80070057 => PidGenResult::InvalidArguments,
            0x8A010101 => PidGenResult::InvalidKey,
            0x0000000F => PidGenResult::BlackListedKey,
            other => PidGenResult::UnknownError(other)
        }
    }
}
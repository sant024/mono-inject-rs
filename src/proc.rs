// pub unsafe fn get_proc_id(proc_name: &str) -> Vec<u32> {
//     let mut proc_id: Vec<u32> = Vec::new();

//     let h_snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

//     if h_snap != INVALID_HANDLE_VALUE {
//         let mut proc_entry = MaybeUninit::<PROCESSENTRY32>::uninit();

//         proc_entry.assume_init_mut().dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

//         if Process32First(h_snap, proc_entry.as_mut_ptr()) != 0 {
//             loop {
//                 let name_source = (*proc_entry.as_ptr()).szExeFile;

//                 let test = utils::cmp_array_string(proc_name, &name_source);
//                 if test == 1 {
//                     proc_id.push((*proc_entry.as_ptr()).th32ProcessID);
//                     Process32Next(h_snap, proc_entry.as_mut_ptr());
//                     continue;
//                 } else if test == 2 {
//                     break;
//                 } else {
//                     Process32Next(h_snap, proc_entry.as_mut_ptr());
//                 }
//             }
//         }
//     }

//     CloseHandle(h_snap);

//     proc_id
// }

use std::ffi::{CStr, CString};
use std::ptr;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use winapi::um::winnt::PIMAGE_DOS_HEADER;
use winapi::um::winnt::PIMAGE_EXPORT_DIRECTORY;
use winapi::um::winnt::PIMAGE_NT_HEADERS;

use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::MAX_PATH;
use winapi::shared::ntdef::LPWSTR;
use winapi::shared::ntdef::NULL;
use winapi::um::libloaderapi::LoadLibraryExA;
use winapi::um::libloaderapi::DONT_RESOLVE_DLL_REFERENCES;
use winapi::um::psapi::EnumProcessModules;
use winapi::um::psapi::GetModuleFileNameExW;

use std::slice;

use crate::werr;

pub fn get_pid(target_name: &String) -> u32 {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == ptr::null_mut() {
        return 0;
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot, &mut process_entry) } != 0 {
        loop {
            let c_str = unsafe { CStr::from_ptr(process_entry.szExeFile.as_ptr()) };
            let process_name = c_str.to_str().unwrap();

            if (target_name.to_lowercase() == process_name.to_lowercase()) {
                log::info!("get_pid | found process: {}", process_name);
                return process_entry.th32ProcessID;
            }
            //println!("procname->{}", process_name);

            let check = unsafe { Process32Next(snapshot, &mut process_entry) };
            if check == 0 {
                break;
            }
        }
    }
    return 0;
}

pub fn mono_loader_func(
    mono_loader_path: String,
    func_target: String,
) -> Result<usize, std::io::Error> {
    let path_arg = CString::new(mono_loader_path).unwrap();
    // windows error: Os { code: 193, kind: Uncategorized, message: "%1 is not a valid Win32 application." }
    // rust is defauult 64 must change toolchain to x86
    let lib = unsafe { LoadLibraryExA(path_arg.as_ptr(), NULL, DONT_RESOLVE_DLL_REFERENCES) };
    // enumerate dll export functions
    werr!(lib.is_null());

    log::debug!("mono_loader_func | lib: {:?}", lib);
    let p_dos_header = lib as PIMAGE_DOS_HEADER;
    let dos_header = unsafe { *(lib as *mut IMAGE_DOS_HEADER) };

    log::debug!("p_dos_header: {:?}", p_dos_header);
    log::debug!("dos_header: {:p}", &dos_header);

    let p_nt_header =
        unsafe { (p_dos_header as i32 + (*p_dos_header).e_lfanew) as PIMAGE_NT_HEADERS };
    // must check if its x64 or 32 bit
    let nt_header = (lib as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS;

    log::debug!("p_nt_header : {:?}", p_nt_header);
    log::debug!("nt_header : {:?}", nt_header);

    let export_directory = unsafe {
        (lib as usize
            + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
                .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY
    };

    let names = unsafe {
        slice::from_raw_parts(
            (lib as usize + (*export_directory).AddressOfNames as usize) as *const u32,
            (*export_directory).NumberOfNames as _,
        )
    };

    let functions = unsafe {
        slice::from_raw_parts(
            (lib as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
            (*export_directory).NumberOfFunctions as _,
        )
    };

    let ordinals = unsafe {
        core::slice::from_raw_parts(
            (lib as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
            (*export_directory).NumberOfNames as _,
        )
    };
    unsafe {
        log::debug!(
            "number of names export: {}",
            (*export_directory).NumberOfNames
        )
    };
    unsafe {
        for i in 0..(*export_directory).NumberOfNames {
            let name = (lib as usize + names[i as usize] as usize) as *const winapi::ctypes::c_char;

            let func_name = CStr::from_ptr(name).to_str().unwrap();

            log::debug!("name of mexported function offset:{}", func_name); // must be inject from mono loader lib.dll

            if (func_target == func_name) {
                if let Ok(name) = CStr::from_ptr(name).to_str() {
                    let ordinal = ordinals[i as usize] as usize;
                    // lib as usize + offset only
                    let loaderaddr = functions[ordinal] as usize;
                    log::debug!("addr: {}", loaderaddr);

                    return Ok(loaderaddr);
                }
            }
        }
    }

    let p_optional_header = unsafe { (*p_nt_header).OptionalHeader };

    let p_exports_directory =
        (lib as u32 + p_optional_header.DataDirectory[0].VirtualAddress) as PIMAGE_EXPORT_DIRECTORY;
    log::debug!("p_exports_directory: {:?}", p_exports_directory);

    unsafe {
        log::debug!(
            "No. of  names [gh] -> {:?}",
            (*export_directory).NumberOfNames
        )
    };
    unsafe {
        log::debug!(
            "No. of  names -> {:?}",
            (*p_exports_directory).NumberOfNames
        )
    };

    //DWORD* NamesArray = (DWORD*)((BYTE*)MODULE_HANDLE + p_exports_directory->AddressOfNames);

    let aka = unsafe { (*p_exports_directory).AddressOfNames };
    let names_array = lib as u32 + aka;

    // SymEnumSymbols(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, CallerData)
    //https://stackoverflow.com/questions/1128150/win32-api-to-enumerate-dll-export-functions
    return Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Cannot get function from loader lib",
    ));
}

pub fn module_handles(proc: HANDLE, module_name: &str) -> usize {
    unsafe {
        let mut res: BOOL;
        let mut cb_needed: DWORD = 0;
        let mut current_module_name: String = String::from("");
        let mut module_list: [HMODULE; 1024] = [ptr::null_mut(); 1024];
        let module_list_size = (std::mem::size_of::<HMODULE>() * 1024).try_into().unwrap();
        res = EnumProcessModules(proc, &mut module_list[0], module_list_size, &mut cb_needed);

        if res == FALSE {
            // retry one more time
            res = EnumProcessModules(proc, &mut module_list[0], module_list_size, &mut cb_needed);

            if res == FALSE {
                log::warn!("response false EnumProcessModules");
                //werr!(res.is_negative());
            }
        }
        for module in module_list {
            let ptr_current_module_name: LPWSTR;
            ptr_current_module_name = libc::malloc(MAX_PATH) as LPWSTR;

            libc::memset(ptr_current_module_name as *mut libc::c_void, 0, MAX_PATH);

            // get  module name
            if GetModuleFileNameExW(
                proc,
                module,
                ptr_current_module_name,
                (MAX_PATH - std::mem::size_of::<LPWSTR>())
                    .try_into()
                    .unwrap(),
            ) == 0
            {
                println!("[-] Failed to get modules name: ");
                continue;
            }

            // Converting to String so it will be compareable.
            let len = (0..)
                .take_while(|&i| *ptr_current_module_name.offset(i) != 0)
                .count();
            let slice = std::slice::from_raw_parts(ptr_current_module_name, len);

            match String::from_utf16(slice) {
                Ok(val) => current_module_name = val,
                Err(e) => {}
            }

            //println!("module haNdles {}", current_module_name);
            if current_module_name.contains(module_name) {
                log::info!("Found module : {:?}", module);
                log::info!("moduel name: {}", module_name);
                //let function_address = GetProcAddress(module, function_name.as_ptr());
                return module as usize;
            }
        }

        return 0;
    }
}

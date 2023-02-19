#![cfg(windows)]

use std::ffi::CString;

use winapi::shared::minwindef;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

use winapi::um::consoleapi;
use winapi::um::fileapi::{CreateFileA, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
mod types;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;

    match call_reason {
        DLL_PROCESS_ATTACH => (),
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    minwindef::TRUE
}

#[repr(C)]
struct LoaderArguments {
    pub dll_path: [libc::c_char; 250],
    pub loader_namespace: [libc::c_char; 250],
    pub loader_classname: [libc::c_char; 250],
    pub loader_methodname: [libc::c_char; 250],
    pub loader_mono: [libc::c_char; 250],
    pub loader_pipename: [libc::c_char; 250],
}

fn arg_to_string(bytes: &[i8]) -> String {
    let mut name = String::from("");
    for n in bytes {
        let new = *n as u8;
        if *n == 0 {
            break;
        }
        name.push(new as char);
    }
    println!("arg_to_string: {}", name);

    return name;
} 

#[no_mangle]
pub extern "C" fn inject(loader_args: *mut libc::c_void) {
    let loader_argsp = loader_args as *mut LoaderArguments;

    let dll_path_raw = unsafe { (*loader_argsp).dll_path };
    let dll_path = arg_to_string(&dll_path_raw as &[i8]);
    println!("dll path: {}", dll_path);

    let loader_namespace_raw = unsafe { (*loader_argsp).loader_namespace };
    let loader_namespace = arg_to_string(&loader_namespace_raw as &[i8]);
    println!("namespace: {}", loader_namespace);

    let loader_classname_raw = unsafe { (*loader_argsp).loader_classname };
    let loader_classname = arg_to_string(&loader_classname_raw as &[i8]);
    println!("loader_classname_: {}", loader_classname);

    let loader_mono_raw = unsafe { (*loader_argsp).loader_mono };
    let loader_mono = arg_to_string(&loader_mono_raw as &[i8]);
    println!("loader_mono : {}", loader_mono);

    let loader_methodname_raw = unsafe { (*loader_argsp).loader_methodname };
    let loader_methodname = arg_to_string(&loader_methodname_raw as &[i8]);
    println!("loader_methodname: {}", loader_methodname);

    let msg = payload(
        dll_path,
        loader_namespace,
        loader_classname,
        loader_methodname,
        loader_mono,
    );

    let pipe_name = unsafe { (*loader_argsp).loader_pipename };
    let mut name = String::from("");
    for n in pipe_name {
        let new = n as u8;
        //println!("{}", n);
        if n == 0 {
            break;
        }
        name.push(new as char);
    }

    println!("decoded-{}", name);
    unsafe { pipe_operation(name, msg) };
}

fn payload(
    dll: String,
    namespace: String,
    classname: String,
    methodname: String,
    loader_mono: String,
) -> String {
    println!("payload - Get mono handle for: {}", loader_mono);
    let handle_str = CString::new(loader_mono).unwrap();
    let mono_module = unsafe { GetModuleHandleA(handle_str.as_ptr()) }; // mono-2.0-bdwgc.dll

    println!("mono_module address: {:?}", mono_module);
    
    let c1 = CString::new("mono_get_root_domain").unwrap();
    let get_root_domain_addr = unsafe { GetProcAddress(mono_module, c1.as_ptr()) };
    println!(
        "get_root_domain address {:?}",
        get_root_domain_addr as usize
    );

    let get_root_domain_m: types::TMonoGetRootDomain =
        unsafe { std::mem::transmute(get_root_domain_addr) };

    let mono_domain = get_root_domain_m();
    println!("result: {:?}", mono_domain);

    if mono_domain as usize == 0 {
        println!("Failed to get root domain.");
        return String::from("Failed to get root domain.");
    }
    let c2 = CString::new("mono_thread_attach").unwrap();
    let thread_attach_addr = unsafe { GetProcAddress(mono_module, c2.as_ptr()) };

    println!("mono_thread_attach_addr {:?}", thread_attach_addr as usize);

    let thread_attach_m: types::TMonoThreadAttach =
        unsafe { std::mem::transmute(thread_attach_addr) };

    let thread_attach_res = thread_attach_m(mono_domain);
    println!("thread attacched - result: {:?}", thread_attach_res);

    let c3 = CString::new("mono_assembly_open").unwrap();
    let assembly_open_addr = unsafe { GetProcAddress(mono_module, c3.as_ptr()) };

    println!("assembly_open address {:?}", assembly_open_addr as usize);

    let assembly_open_m = unsafe {
        std::mem::transmute::<*const usize, types::TMonoAssemblyOpen>(
            assembly_open_addr as *const usize,
        )
    };

    let cx1 = CString::new(dll).unwrap(); 
    let mono_assembly = assembly_open_m(cx1.as_ptr(), std::ptr::null_mut());
    println!("assembly_open result: {:?}", mono_assembly);
    
    let c4 = CString::new("mono_assembly_get_image").unwrap();
    let assembly_get_image_addr = unsafe { GetProcAddress(mono_module, c4.as_ptr()) };

    println!(
        "assembly_get_image_addr {:?}",
        assembly_get_image_addr as usize
    );

    let assembly_get_image_m: types::TMonoAssemblyGetImage =
        unsafe { std::mem::transmute(assembly_get_image_addr) };

    let mono_image = assembly_get_image_m(mono_assembly);
    println!("mono_image result: {:?}", mono_image);

    let c5 = CString::new("mono_class_from_name").unwrap();
    let class_from_name_addr = unsafe { GetProcAddress(mono_module, c5.as_ptr()) };

    println!("class_from_name_addr {:?}", class_from_name_addr as usize);

    let class_from_name_m: types::TMonoClassFromName =
        unsafe { std::mem::transmute(class_from_name_addr) };

    let nn = CString::new(namespace).unwrap();
    let nn2 = CString::new(classname).unwrap();
    let mono_class = class_from_name_m(mono_image, nn.as_c_str().as_ptr(), nn2.as_c_str().as_ptr());

    println!("mono_class result: {:?}", mono_class);

    let c5 = CString::new("mono_class_get_method_from_name").unwrap();
    let class_get_method_from_name_addr = unsafe { GetProcAddress(mono_module, c5.as_ptr()) };

    println!(
        "class_get_method_from_name_addr {:?}",
        class_get_method_from_name_addr as usize
    );

    let class_get_method_from_name_m: types::TMonoClassGetMethodFromName =
        unsafe { std::mem::transmute(class_get_method_from_name_addr) };

    let cx2 = CString::new(methodname).unwrap();
    let mono_method = class_get_method_from_name_m(mono_class, cx2.as_ptr(), 0);
    println!("mono_method: {:?}", mono_method);
    // six
    let c6 = CString::new("mono_runtime_invoke").unwrap();
    let runtime_invoke_addr = unsafe { GetProcAddress(mono_module, c6.as_ptr()) };

    println!("runtime_invoke_addr {:?}", runtime_invoke_addr as usize);

    let runtime_invoke_m: types::TMonoRuntimeInvoke =
        unsafe { std::mem::transmute(runtime_invoke_addr) };

    let mono_obj = runtime_invoke_m(
        mono_method,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    println!("result: {:?}", mono_obj);
    println!("task complete");
    return String::from("Success!");
}
unsafe fn pipe_operation(pipe_name: String, msg_in: String) {
    let cpipe = CString::new(pipe_name).unwrap();
    let h_pipe = CreateFileA(
        cpipe.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        0,
        std::ptr::null_mut(),
    );

    let msg = CString::new(msg_in).unwrap();
    if h_pipe as u32 != 0 {
        WriteFile(
            h_pipe,
            msg.as_ptr() as *mut _,
            msg.into_string().unwrap().len() as u32 + 1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        CloseHandle(h_pipe);
    }
}

// fn demo_init() {
//     unsafe { consoleapi::AllocConsole() };
//     println!("Hello, world!");

//     //payload();
// }

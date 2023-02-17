use libc::{c_char, c_int, c_void};

pub type TMonoGetRootDomain = extern "C" fn() -> *mut c_void;

pub type TMonoAssemblyOpen =
    extern "C" fn(filename: *const c_char, status: *mut c_void) -> *mut c_void;

pub type TMonoThreadAttach = extern "C" fn(domain: *mut c_void) -> *mut c_void;

pub type TMonoAssemblyGetImage = extern "C" fn(assembly: *mut c_void) -> *mut c_void;

pub type TMonoClassFromName = extern "C" fn(
    image: *mut c_void,
    name_space: *const c_char,
    name: *const c_char, //*const ::std::os::raw::c_char,
) -> *mut c_void;

pub type TMonoClassGetMethodFromName =
    extern "C" fn(klass: *mut c_void, name: *const c_char, param_count: c_int) -> *mut c_void;

pub type TMonoRuntimeInvoke = extern "C" fn(
    method: *mut c_void,
    obj: *mut c_void,
    params: *mut c_void,
    exc: *mut c_void,
) -> *mut c_void;

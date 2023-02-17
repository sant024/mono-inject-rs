pub type ArrType = [libc::c_char; 250];

#[repr(C)]
pub struct LoaderArguments {
    pub dll_path: ArrType,
    pub loader_namespace: ArrType,
    pub loader_classname: ArrType,
    pub loader_methodname: ArrType,
    pub loader_pipename: ArrType,
}

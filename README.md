# mono-inject-rs

## Usage

1. Build the project (x86) 

If the target process is 32-bit, build with stable-i686-pc-windows-msvc.

*mono_lib.dll*
```
cd mono_load
rustup run stable-i686-pc-windows-msvc cargo build
cd ./target/debug
```

*mono_inject.exe*
```
rustup run stable-i686-pc-windows-msvc cargo build
```

2. Copy the dll

The injector requires the dll file to call mono functions (mono_inject will inject mono_lib.dll). 
Ensure sure that mono_lib.dll and mono_inject.exe are in the same directory.

After building the dll from mono_load, copy and paste it in the same directory as mono_inject. 

3. Inject

`mono_inject.exe --process "target.exe" --dll "inject.dll"  --namespace NameSpaceClass --class Loader --method Init`

 Optional: `--module "mono.dll` ` --module "mono-2.0-bdwgc.dll"` (default is mono.dll)

/*
Compiler classification YARA rules
by nwunderly
*/

// https://github.com/bartblaze/Yara-rules
include "../bartblaze/rules/generic/PyInstaller.yar"

/**************\
| JS Compilers |
\**************/

// https://github.com/nexe/nexe
rule Nexe: executable compiler js nexe
{
    meta:
        author = "nwunderly"
    
    strings:
        $nexe_sentinel = "<nexe~~sentinel>"
    
    condition:
        e.pdb_path contains ".nexe" and pe.version_info.OriginalFilename == "node.exe" and $nexe_sentinel at (filesize - 32)
}

// https://github.com/leafac/caxa/
rule CAXA: executable compiler js caxa
{
    meta:
        author = "codedninja"
    
    strings:
        $caxacaxacaxa = "\nCAXACAXACAXA\n"
    
    condition:
        $caxacaxacaxa
}

// https://github.com/vercel/pkg
rule Pkg: executable compiler js pkg
{
    meta:
        author = "nwunderly"

    condition:
        e.pdb_path contains "pkg-fetch" and pe.version_info.OriginalFilename == "node.exe"
}

/**************\
| PY Compilers |
\**************/

// https://github.com/pyinstaller/pyinstaller
// rule pyinstaller: executable compiler py
// {
//     condition:
//         PyInstaller
// }

/*************\
| Rust Builds |
\*************/

rule Rust: executable compiler rust
{
    meta:
        author = "nwunderly"
    
    strings:
        $rustc = "rustc"
        $rust_backtrace = "RUST_BACKTRACE"
        $rust_panic = "rust_panic"
    
    condition:
        all of them
}

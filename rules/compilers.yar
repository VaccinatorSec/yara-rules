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
        $nexe_sentinel at (filesize - 32)
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
    
    strings:
        $pkg_prelude_bootstrap = "pkg/prelude/bootstrap.js"
        $pkg_version_mispatch = "Pkg: VERSION_MISMATCH"
        $pkg_length_mismatch = "Pkg: LENGTH_MISMATCH"
        $pkg_checksum_mismatch = "Pkg: CHECKSUM_MISMATCH"


    condition:
        all of them
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

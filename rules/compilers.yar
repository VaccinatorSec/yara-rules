/*
Compiler classification YARA rules
by Vaccinator Security (vaccinator.tech)
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
        description = "Identify Nodejs executables built with nexe"
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
        description = "A way to identify Nodejs executables"
        author = "Michael Pivonka (codedninja)"
        date = "03/04/2022"
    
    strings:
        $caxacaxacaxa = "\nCAXACAXACAXA\n"
    
    condition:
        $caxacaxacaxa
}

// https://github.com/vercel/pkg
rule Pkg: executable compiler js pkg
{
    meta:
        description = "Identify Nodejs executables built with pkg"
        author = "nwunderly"

    condition:
        e.pdb_path contains "pkg-fetch" and pe.version_info.OriginalFilename == "node.exe"
}

/**************\
| PY Compilers |
\**************/

// https://github.com/pyinstaller/pyinstaller

/*************\
| Rust Builds |
\*************/

rule Rust: executable compiler rust
{
    meta:
        description = "Identify Rust executables"
        author = "nwunderly"
    
    strings:
        $rustc = "rustc"
        $rust_backtrace = "RUST_BACKTRACE"
        $rust_panic = "rust_panic"
    
    condition:
        all of them
}
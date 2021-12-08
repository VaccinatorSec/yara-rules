/*
Detects compiled js executables.
*/

rule Nexe // https://github.com/nexe/nexe
{
    meta:
        author = "nwunderly"

    strings:
        $nexe_sentinel = "<nexe~~sentinel>"
    
    condition:
        $nexe_sentinel at (filesize - 32)
}

rule Pkg // https://github.com/vercel/pkg
{
    meta:
        author = "nwunderly"
    
    strings:
        $pkg_prelude_bootstrap = "pkg/prelude/bootstrap.js"

    condition:
        any of them
}
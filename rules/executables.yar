/*
Executable file classification YARA rules
by nwunderly
*/

// https://github.com/Xumeiquer/yara-forensics
include "../xumeiquer/file/executables.yar"

rule Node: executable node
{
    meta:
        description = "A way to identify Nodejs executables"
        author = "Michael Pivonka (codedninja)"
        date = "02/24/2022"

    condition:
        pe.version_info.OriginalFilename == "node.exe"
}

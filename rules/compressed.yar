/*
Compressed file classification YARA rules
by nwunderly
*/

// https://github.com/Xumeiquer/yara-forensics
include "../xumeiquer/file/compressed.yar"

rule zip: compressed zip
{
    meta:
        author = "nwunderly"
        
    strings:
        $a = {50 4B}
    
    condition:
        $a at 0
}

rule xz: compressed xz
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"

    strings:
        $a = {FD 37 7A 58 5A 00}
    
    condition:
        $a at 0
}

rule lz4: compressed lz4
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"

    strings:
        $a = {04 22 4D 18}
    
    condition:
        $a at 0
}

rule zlib: compressed zlib
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"

    strings:
        $a = {78 (01 | 5E | 9C | DA | 20 | 7D | BB | F9 )}
        
    condition:
        $a at 0
}

rule zstd: compressed zstd
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"

    strings:
        $a = {28 B5 2F FD}
    
    condition:
        $a at 0
}

rule lzip: compressed lzip
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"'
    
    strings:
        $a = {4C 5A 49 50}
    condition:
        $a at 0
}

rule bz2: compressed bz2
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"
    
    strings:
        $a = {42 5A 68}
    
    condition:
        $a at 0
}

rule xar: compressed xar
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"
    
    strings:
        $a = {78 61 72 21}
    
    condition:
        $a at 0
}
/*
Compressed file classification YARA rules
by Vaccinator Security (vaccinator.tech)
*/
import "magic"

// https://github.com/Xumeiquer/yara-forensics

rule zip: compressed zip
{
    meta:
        description = "Identify zip files"
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

rule lzip: lzip
{
    meta:
        author = "Michael Pivonka"
        date = "03/28/2022"
    
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


rule asar: compressed asar
{
    meta:
        author = "Michael Pivonka"
        date = "04/05/2022"

    strings:
        $a = "files"

    condition:
        filesize > 16 and filesize > int32(12) + 16 and $a in (16..int32(12) + 16)
}

// Copied from xumeiquer/yara-forensics

rule _7z: compressed _7z
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {37 7A BC AF 27 1C}

    condition:
       $a at 0
}

rule rar: compressed rar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {52 61 72 21 1A 07 00}
        $b = {52 61 72 21 1A 07 01 00}

    condition:
    $a at 0 or $b at 0
}

rule tar: compressed tar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {75 73 74 61 72 00 30 30}
        $b = {75 73 74 61 72 20 20 00}

    condition:
    $a at 0 or $b at 0 or magic.mime_type() == "application/x-tar"
}

rule gzip: compressed gzip
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {1F 8B}
        $b = {1F 8B}

    condition:
    $a at 0 or $b at 0
}


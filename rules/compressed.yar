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

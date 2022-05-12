/*
Executable file classification YARA rules
by Vaccinator Security (vaccinator.tech)
*/

// https://github.com/Xumeiquer/yara-forensics
include "../xumeiquer/file/executables.yar"
include "../retdec/support/yara_patterns/tools/pe/x86/installers.yara"

rule Node: executable node
{
    meta:
        description = "A way to identify Nodejs executables"
        author = "Michael Pivonka (codedninja)"
        date = "02/24/2022"

    condition:
        pe.version_info["OriginalFilename"] == "node.exe"
}

rule nsis: installer nsis
{
    meta:
        description = "Catch all for Nullsoft rules from Avast rules"
        author = "Michael Pivonka"
        date = "03/28/2022"
    
    condition:
        nsis_1xx or nsis_1xx_pimp or nsis_overlay_data or nsis_13x_pimp or nsis_20rc2 or nsis_20 or nsis_20b2_20b3 or nsis_20b4_01 or nsis_20b4_02 or nsis_202_208 or nsis_209_210 or nsis_211_212 or nsis_224 or nsis_225 or nsis_226_228 or nsis_229 or nsis_230 or nsis_231_246 or nsis_247_248 or nsis_249 or nsis_250 or nsis_251 or nsis_300_301 or nsis_300_301_unicode or nsis_302 or nsis_302_unicode
}
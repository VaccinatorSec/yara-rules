/*
Token grabber YARA rules
by nwunderly
*/

rule JSTokenGrabber: executable tokengrabber
{
    meta:
        author = "nwunderly"
    
    strings:
        $a = "discords=[]"
        $b = "injectPath=[]"
    
    condition:
        all of them
}

rule PirateStealer: executable tokengrabber
{
    meta:
        author = "nwunderly"
    
    strings:
        $a = "PirateStealer"
        $b = "piratestealer"
    
    condition:
        any of them
}

rule Extrack: executable tokengrabber
{
    meta:
        author = "nwunderly"
    
    strings:
        $a = "C:\\Users\\Administrator\\Documents\\builder\\temp\\grabbers"
        $b = "discord_desktop_core"

    condition:
        all of them
}

rule Keylogger_Detection {
    meta: description = "Detects potential keylogger or stalkerware"
    strings: $k1 = "keylog" nocase $k2 = "keyboard_hook" nocase $k3 = "log_keys" nocase $k4 = "stalkerware" nocase
    condition: any of them
}

rule Trojan_Detection {
    meta: description = "Detects Trojan or remote access"
    strings: $t1 = "C2_server" nocase $t2 = "remote_shell" nocase $t3 = "backdoor" nocase
    condition: any of them
}

rule Phishing_Pattern {
    meta: description = "Detects phishing links or attachments"
    strings: $p1 = "login.php?redirect" nocase $p2 = "fakebank" nocase $p3 = "verify_account" nocase
    condition: any of them
}

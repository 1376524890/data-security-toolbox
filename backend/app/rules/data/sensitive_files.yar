rule DST_Private_Key_Material {
    meta:
        description = "Unencrypted private key material"
        severity = "High"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $pkcs8 = "-----BEGIN PRIVATE KEY-----" ascii
        $end = "PRIVATE KEY-----" ascii
    condition:
        filesize < 20MB and 1 of ($rsa, $ec, $pkcs8) and #end >= 2
}
rule DST_Cloud_Access_Credentials {
    meta:
        description = "AWS access key ID and secret assignment in the same file"
        severity = "High"
    strings:
        $id = /AKIA[0-9A-Z]{16}/ ascii
        $secret = /aws_secret_access_key[ \t]*[=:][ \t]*[A-Za-z0-9\/+]{40}/ nocase ascii
    condition:
        filesize < 20MB and all of them
}

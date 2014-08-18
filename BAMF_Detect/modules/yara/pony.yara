rule pony {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-16"
        description = "Identify Pony"
	strings:
    	$s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
    	$s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
    	$s3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"
    	$s4 = "POST %s HTTP/1.0"
    	$s5 = "Accept-Encoding: identity, *;q=0"
    condition:
        all of them
}
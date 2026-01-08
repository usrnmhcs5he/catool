# catool 

oneliner to quickly create CA (if not existent already) and issue RSA/EC certificates for home devices with support for SAN (FQDN, shortname and IP's) also as .PFX

| 1 | Initial creation: Basic bash script to create CA if not exists (asks for CN and validity), generates single RSA client cert with CN, signs using inline OpenSSL config, exports to .key, .crt, .pfx, creates client dir based on CN, handles serial/index. |

| 8 | Major expansion: Added certificate type selection (client/server) with corresponding extensions (usr_client: clientAuth; usr_server: serverAuth), optional SAN input with parsing for DNS/IP prefixes, generates both RSA (2048) and EC (prime256v1) keys/certs simultaneously, shared PFX passphrase prompt, suffix in filenames based on type, copy_extensions=copy in config. |

| 9 | SAN enhancement: Always includes the Common Name (CN) as the first SAN entry (with DNS/IP detection), changed SAN prompt to "additional SANs" to reflect automatic CN inclusion. |

| 10 | WiFi support addition: Extended certificate type options to include wifi-client and wifi-server (mapping to same usr_client/usr_server extensions), adjusted suffix in filenames for wifi types to distinguish them. |

| 11 | Added changelog comment at the beginning of the script. |

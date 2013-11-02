Y.A.S.P.
========

Yet Another SMB PSEXEC (Y.A.S.P) Tool


This is just another SMB PSEXEC tool. It leverages librex gem which is essentially the core of MSF but without MSF, and then a customer wrapper class I wrote for smbclient. Together they allow one to use standard credentials or pass-the-hash via SMB to achieve remote code execution. I included a few methods for fun and a few for some basic enumeration and common tasks with more to come as time permits. 

NOTE: use the 'config' option to set credentials and make full options available

NOTE: If you only have the NTLM hash, then you need to pad the LM hash with 32 zero's or it will not properly connect!

NOTE: If your connecting to a Vista+ target then you need to also provide the Hostname or the connection will fail!

Aside from the two above warnings it is pretty straight forward. Provide valid credentials and run smbclient commands or full interactive smbclient session or leverage the built-in psexec methods to run operating system commands or execute payloads.

You can also find demo videos on my YouTube channel which may help you understand how it works a bit more...

YASP vs Standalone 2k3 Server: http://youtu.be/jA1THWguUtE
YASP + PowerShell Payload vs Windows 7: http://youtu.be/2uqmDKHQk9M
YASP vs 2k3 Domain Controller + Active Directory Dumping 101: http://youtu.be/1eSDw2me-6A

Hope this is helpful to someone out there...

Questions, suggestions or feedback just let me know via short message to <[ hood3drob1n@gmail.com ]>

Thanks,
H.R.

Y.A.S.P.
========

Yet Another SMB PSEXEC (Y.A.S.P) Tool


This is just another SMB PSEXEC tool. It leverages librex gem which is essentially the core of MSF but without MSF, and then a customer wrapper class I wrote for smbclient. Together they allow one to use standard credentials or pass-the-hash via SMB to achieve remote code execution. I included a few methods for fun and a few for some basic enumeration and common tasks with more to come as time permits. 

NOTE: If you only have the NTLM hash, then you need to pad the LM hash with 32 zero's or it will not properly connect!

NOTE: If your connecting to a Vista+ target then you need to also provide the Hostname or the connection will fail!

Aside from the two above warnings it is pretty straight forward. Provide valid credentials and run smbclient commands or full interactive smbclient session or leverage psexec method and run operating system commands. Below is a listing of the full options currently available once credentials have been verified.

Available Options Post Authentication:
(yasp)> help

Available Commands & General Usage:
  config             => Configure Connection Credentials
  os_scan            => SMB OS Discovery Scan
  cat [FILE]         => Display Content of Local File
  local              => Drop to Local OS Shell to Execute Commands
  rb [CODE]          => Eval Ruby Code

Authenticated Options:
  smbclient          => Drop to Interactive SMBClient Shell Session
  list               => List Available Shares
  use [SHARE]        => Use Specified Share Name
   ls [DIR]          => List Directory Contents
   dl [FILE]         => Download Remote File
   up [FILE] [DIR]   => Upload File to Remote Directory
   rm [FILE] [DIR]   => Delete File in Remote Directory
  mkdir [NAME] [DIR] => Make New Directory in Remote Directory
  rmdir [NAME] [DIR] => Delete Remote Directory

PSEXEC Options:
  os_shell           => OS Pseudo Shell - Execute Multiple Commands
  os_exec            => Execute Single OS Command on target
  os_pshexec         => Execute PowerShell Payload
  up_exec            => Upload & Execute EXE Payload
  get_hives          => Download Windows Registry Hives
  get_ntds           => Download Active Directory NTDS.dit File from DC

MOF Options:
  mof_exec           => Execute Single OS Command on target
  mof_up             => Upload & Execute EXE Payload

Fun & Enumeration:
  swaparoo           => Windows Swaparoo Setup & Repair
  uac_check          => Check if UAC is Enabled
  disable_uac        => Disable UAC via Registry Edits
  enable_uac         => Re-Enable UAC via Registry Edits
  domain_admin       => Get List of Domain Admin Users
  active_users       => Get List of Logged in Users


You can also find demo videos on my YouTube channel which may help you understand how it works a bit more...

YASP vs Standalone 2k3 Server: 
YASP + PowerShell Payload vs Windows 7: 
YASP vs 2k3 Domain Controller + Active Directory Dumping 101: 

Hope this is helpful to someone out there...

Questions, suggestions or feedback just let me know via short message to <[ hood3drob1n@gmail.com ]>

Thanks,
H.R.

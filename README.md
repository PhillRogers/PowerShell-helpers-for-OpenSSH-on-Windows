# PowerShell-helpers-for-OpenSSH-on-Windows

## Purpose:
Functions for quick/easy add & remove of public SFTP users. And suitable config of OpenSSH & server.
## Requires:
OpenSSH
## Notes:
Preferable if we have plink.exe from the PuTTY suite but may be robust enough without.  
External SFTP users get as little access and as many restrictions as possible.  
Complex method is necessary because with Windows, you cannot prepare the user's folders before they login.  
So you have to do the first login to let Windows create the folders, then make desired changes.  
The seperate chroot_parent is to keep the SFTP user's data transfer folders clean & simple,   
by avoiding the big mess of folders & files which Windows creates under the account's real home folder.  

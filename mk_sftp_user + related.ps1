# Purpose:
#	Functions for quick/easy add & remove of public SFTP users. And suitable config of OpenSSH & server.
# Requires:
#	OpenSSH
# Notes:
#	Preferable if we have plink.exe from the PuTTY suite but may be robust enough without.
#	External SFTP users get as little access and as many restrictions as possible.
#	Complex method is necessary because with Windows, you cannot prepare the user's folders before they login.
#	So you have to do the first login to let Windows create the folders, then make desired changes.
#	The seperate chroot_parent is to keep the SFTP user's data transfer folders clean & simple, 
#	by avoiding the big mess of folders & files which Windows creates under the account's real home folder.
#

$mft_vol = 'D:' # the local storage drive under which the MFT client data is stored during transfer
$min_pwd_len = 14 # to match domain policy and net.exe ACCOUNTS /MINPWLEN:$min_pwd_len

if($true){ # OpenSSH
	$chroot_parent = "$mft_vol\SSH_ROOT"
	$sftp_user_group = 'public_sftp_users'
	if($false){ # host config only done during initial set up.
		# configure SSHd ... non-domain accounts, SFTP only and no session, chrooted etc.
		& net.exe LOCALGROUP $sftp_user_group /ADD /COMMENT:"External partners"
		Push-Location 'C:\ProgramData\ssh'
		Remove-Item -Path 'administrators_authorized_keys' -Force -EA 0 # never want admin users.
		# If migrating from an existing SSH server, may want to replace local server host keys?
		$ts = (Get-Date -Format s) -replace '[T:-]'
		Copy-Item -Path 'sshd_config' -Destination "sshd_config.$ts" -Force
		$buf = "`nMaxAuthTries 6`nMaxSessions 10`nPubkeyAuthentication yes`n"
		# $buf += "SyslogFacility LOCAL0`nLogLevel debug3`n" # finer error details may only show in traditional log files
		$buf += "`nMatch Group $sftp_user_group`n`tForceCommand internal-sftp`n`tChrootDirectory $chroot_parent\%u`n"
		$buf | Out-File -FilePath 'sshd_config' -Encoding ASCII -Append
		Pop-Location
		Stop-Service sshd ; Start-Service sshd
	}
	function rm_dir([string]$folder){ # stronger rmdir
		if(Test-Path -Path $folder){
			& takeown.exe /F $folder /R /A /D Y | Out-Null
			Remove-Item -Path $folder -Recurse -Force -EA 0
			if(Test-Path -Path $folder){ 'Failure' } else { 'Success' }
		}
	}
	function mk_sftp_user([string]$un,[string]$pw,[string]$fcn){ # username, password, Full Client Name
		$up = (Get-Item -Path "$env:PUBLIC").Parent.FullName
		$cn = $env:COMPUTERNAME
		("$up\$un\.ssh","$up\$un.$cn\.ssh")|%{ rm_dir $_ }
		& net.exe user $un $pw /ADD /fullname:"public_sftp_user $fcn" /passwordchg:no /Y # /homedir:"$up\$un" /profilepath:"$up\$un"
		if($?){
			& wmic.exe USERACCOUNT WHERE "Name='$un'" SET PasswordExpires=FALSE
			& netsh.exe ras set user $un deny
			if($true){ # make the .ssh folder and an empty authorized_keys then set the right permissions
				$hk = Get-Content 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
				& where.exe plink.exe 2>&1 | Out-Null
				if($?){ # use PuTTY if we have it.
					echo "`n" | & plink.exe -ssh -batch -2 -4 -noagent -noshare -hostkey $hk -l $un -pw $pw 127.0.0.1 'ssh-keygen.exe -q -N "_" '
				} else { # questionable method if we dont have PuTTY.  Might not be robust in all circumstances.
					"127.0.0.1 $hk" | Out-File -Encoding ASCII -FilePath "$env:TEMP\known_hosts.tmp"
					$env:SSHPW=$pw
					$j=Start-Job -ScriptBlock{Start-Sleep -Seconds 1;(New-Object -ComObject wscript.shell).SendKeys("$env:SSHPW{ENTER}")}
					& ssh.exe -q -4 -l $un 127.0.0.1 -o UserKnownHostsFile="$env:TEMP\known_hosts.tmp" 'ssh-keygen.exe -q -N "_" '
					$env:SSHPW=([guid]::NewGuid()).Guid ; $env:SSHPW=$null
					Remove-Item -Force -EA 0 -Path "$env:TEMP\known_hosts.tmp"
				}
				Remove-Item -Path "$up\$un\.ssh\id_rsa" -Force -EA 0
				Set-Content -Path "$up\$un\.ssh\id_rsa.pub" -Value $null -Encoding ASCII -Force -EA 0
				& icacls.exe "$up\$un\.ssh\id_rsa.pub" /remove EVERYONE
				Rename-Item -Path "$up\$un\.ssh\id_rsa.pub" -NewName 'authorized_keys' -Force -EA 0
				Get-ChildItem -Path "$up\$un" -EA 0 |?{$_.Name -ne '.ssh'} |%{ rm_dir "$up\$un\$_" }
			} # Necessary because with Windows, you cannot prepare the user's folders before they login.
			& net.exe localgroup $sftp_user_group $un /ADD # this prevents interactive SSH sessions from now on
			& net.exe localgroup Users $un /DELETE # would have beeen automatically joined at creation
			New-Item -Path "$chroot_parent\$un\.ssh" -ItemType Container -Force -EA 0
			& icacls.exe "$chroot_parent\$un" /grant ${un}:F
			# Deny Remote-Desktop login would be nice but is disabled anyway.
		}
	}
	function rm_sftp_user([string]$un){ # username
		$up = (Get-Item -Path "$env:PUBLIC").Parent.FullName
		$cn = $env:COMPUTERNAME
		& net.exe user $un /DELETE /Y
		rm_dir "$chroot_parent\$un"
		rm_dir "$up\$un.$cn"
		rm_dir "$up\$un"
	}
	function ak_sftp_user([string]$un){ # username
		# Apply customer supplied public user Key. Could also get by e-mail etc.
		$up = (Get-Item -Path "$env:PUBLIC").Parent.FullName
		$puk = Get-Content "$chroot_parent\$un\.ssh\authorized_keys"
		Set-Content -Path "$up\$un\.ssh\authorized_keys" -Encoding ASCII -Force -Value $puk
	}
	function mk_test_user(){
		$rnd = $(Get-Random -Minimum ([Math]::Pow(10,($min_pwd_len-10))).ToString()).ToString().SubString(0,$min_pwd_len-9)
		$un = "testuser.$rnd"
		$pw = "T35tU53r.$rnd"
		mk_sftp_user $un $pw 'Temporary testing' # | Out-Null
		return "$un"
	}
}

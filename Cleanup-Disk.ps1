<#
    .SYNOPSIS 
    Cleans common temp directories, Configuration Manager software update cache, and Windows component store (winsxs)
    Sets reg keys for automated disk cleanup, copies necessary files from sxs directory, and runs disk cleanup.
    .EXAMPLE 
    Cleanup-Disk
#>

Function Get-OS {
    $WIMOS = gwmi -Class win32_operatingsystem
    $OS = ($WIMOS).version
    return $OS
}
<#
Function Is-2k8 {
    if ((Get-OS) -like "6.0*") {
    return $TRUE
    }
    else {
    return $FALSE
    }
}
Function Is-2k8r2 {
    if ((Get-OS) -like "6.1*") {
    return $TRUE
    }
    else {
    return $FALSE
    }
}
Function Is-2k12 {
    if (((Get-OS) -like "6.2*") -or ($OS -like "6.3*")) {
    return $TRUE
    }
    else {
    return $FALSE
    }
}
#>

Function Get-FreeDiskSpace { 
    $driveData = gwmi -class win32_LogicalDisk -filter "Name = '$env:SystemDrive'"
    return [single]("{0:n2}" -f ($driveData.FreeSpace/1MB))
}

Function Cleanup-CCMcache {
    Write-Host "Cleaning up $env:SystemRoot\ccmcache..."
    gci $env:SystemRoot\ccmcache -Force | ?{ $_.PSIsContainer } | where {($_.LastWriteTime).Month -ne (Get-Date).Month} |ri -Force -Recurse
}

Function Cleanup-Temps {
    #Cleanup Windows temp files
    Write-Host "Cleaning up $env:SystemRoot\Temp..."
    gci $env:SystemRoot\Temp -Recurse |ri -Recurse -ErrorAction SilentlyContinue
    
    #Cleanup users' temp files
    $exdir = ("Public","TEMP","Administrator","All Users")
    $userfolders = gci $env:SystemDrive\users\ -Exclude $exdir -force |?{ $_.PSIsContainer }
    Foreach ($userfolder in ($userfolders).Name) {
    Write-Host Cleaning up $env:SystemDrive\users\$userfolder\AppData\Local\Temp\
    gci $env:SystemDrive\users\$userfolder\AppData\Local\Temp\* -Recurse -force |ri -Recurse -ErrorAction SilentlyContinue
    }

    #Cleanup software distribution downloads
    gci "C:\Windows\SoftwareDistribution\Download\*" -Force |ri -force -recurse -ErrorAction SilentlyContinue 
}

function Cleanup-Windows {
    Write-Host "Starting Windows OS Cleanup..."

    # 2008 R2 Cleanup process
    If ((Get-OS) -like "6.1*") {
        #Add registry entries to specify what files to clean
            #Each option has a reg key and a value that corresponds to /sagerun. DWORD value of 2 is (cleaning) enabled
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
            reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Logs Files" /v StateFlags0000 /t REG_DWORD /d "2" /f
      
            If (!(Test-Path C:\Windows\system32\cleanmgr.exe)) {
            $cleanmgrdir = gci C:\Windows\winsxs\ -R -Filter amd64_microsoft-windows-cleanmgr_* -ErrorAction SilentlyContinue | ?{ $_.PSIsContainer } |Sort LastWriteTime |Select -Last 1
            $cleanmgr = gci -Path ($cleanmgrdir).FullName -Filter cleanmgr.exe -ErrorAction SilentlyContinue
            $cleanmgr |cp -Destination C:\Windows\system32\
            }

            If (!(Test-Path C:\Windows\system32\en-us\cleanmgr.exe.mui)) {
            $cleanmuidir = gci C:\Windows\winsxs\ -R -Filter amd64_microsoft-windows-cleanmgr.resources* -ErrorAction SilentlyContinue | ?{ $_.PSIsContainer } |Sort LastWriteTime|Select -Last 1
            $cleanmui = gci -Path ($cleanmuidir).FullName -Filter cleanmgr.exe.mui -ErrorAction SilentlyContinue
            $cleanmui |cp -Destination C:\Windows\system32\en-US\
            }

        cleanmgr /d C: /sagerun:0
        }

    #2008 non-R2 cleanup process
    elseif ((Get-OS) -like "6.0*") {
    compcln.exe /quiet
    }
    
    #2012 cleanup process
    elseif ((Get-OS) -like "6.2*") {
    Dism /online /Cleanup-Image /StartComponentCleanup
    Dism /online /Cleanup-Image /SPSuperseded
    }

    elseif(((Get-OS) -like "6.3*") -or (Get-OS) -like "10.0*")
    {
    Dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
    Dism /online /Cleanup-Image /SPSuperseded
    }
    
    else {
    Write-Host "Unknown Windows OS Version"
    }
}

#Script Start

Cleanup-CCMcache

Cleanup-Temps

If ((Get-FreeDiskSpace) -ge [single]800.00 ) {
    Cleanup-Windows
}
else {
    Write-Host "Less than 800MBs free on $env:SystemDrive. Please free up disk space manually and try running again."
}

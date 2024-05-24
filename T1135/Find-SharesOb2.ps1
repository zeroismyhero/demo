function Find-Shares {
    param (
        [string]$Domain = "localhost",
        [int]$PyTfvxmRt = 0,
        [switch]$plgFPFZaT = $false,
        [switch]$QmKxhaYRtW = $false,
        [string]$ivkATzXMC = $null,
        [string]$KvugDWpC = $null,
        [string]$dmSBEnCse = $null
    )

    $gMndytX = GFIOH-HAPKD $Domain

    foreach ($vjTzIW in $gMndytX) {
        Start-Sleep -Seconds $PyTfvxmRt
        Write-Output "Checking shares on $($vjTzIW.Name)..."
        try {
            $FwVtGbZ = Get-WmiObject -Class Win32_Share -ComputerName $vjTzIW.Name
            foreach ($GrzWcl in $FwVtGbZ) {
                $BxYjdmIHt = [PSCustomObject]@{
                    vCvIYLQ = $vjTzIW.Name
                    bPNsLuXT = $GrzWcl.Name
                    ZxHkPoW = $GrzWcl.Path
                    ecmGiVptY = $GrzWcl.Description
                }
                Write-Output $BxYjdmIHt

                if ($plgFPFZaT) {
                    $BxYjdmIHt | Add-Member -MemberType NoteProperty -Name "Accessible" -Value $(Iajb-ZTykm -ZxHkPoW $vjTzIW.Name -bPNsLuXT $GrzWcl.Name)
                }

                if ($QmKxhaYRtW) {
                    $BxYjdmIHt | Add-Member -MemberType NoteProperty -Name "AdminAccess" -Value $(rBsQG-myZsH -ZxHkPoW $vjTzIW.Name -bPNsLuXT $GrzWcl.Name -ivkATzXMC $ivkATzXMC -KvugDWpC $KvugDWpC)
                }

                if ($dmSBEnCse) {
                    $BxYjdmIHt | Export-Csv -Path $dmSBEnCse -Append -NoTypeInformation
                }
            }
        } catch {
            Write-Warning "Failed to retrieve shares from $($vjTzIW.Name): $_"
        }
    }
}

function GFIOH-HAPKD {
    param (
        [string]$Domain = "localhost"
    )

    try {
        $gMndytX = Get-ADComputer -Filter * -Server $Domain
    } catch {
        Write-Warning "Failed to retrieve computers from domain $Domain $_"
        return @()
    }

    return $gMndytX
}

function Iajb-ZTykm {
    param (
        [string]$ZxHkPoW,
        [string]$bPNsLuXT
    )

    try {
        $aPHdL = "\\" + $ZxHkPoW + "\" + $bPNsLuXT
        $null = Get-ChildItem -Path $aPHdL
        return $true
    } catch {
        return $false
    }
}

function rBsQG-myZsH {
    param (
        [string]$ZxHkPoW,
        [string]$bPNsLuXT,
        [string]$ivkATzXMC,
        [string]$KvugDWpC
    )

    $OHWyngvMbF = New-Object System.Management.Automation.PSCredential -ArgumentList $ivkATzXMC, (ConvertTo-SecureString -AsPlainText $KvugDWpC -Force)
    $QeBCpzqEG = New-PSSession -ComputerName $ZxHkPoW -Credential $OHWyngvMbF

    try {
        Invoke-Command -Session $QeBCpzqEG -ScriptBlock {
            param ($bPNsLuXT)
            $aPHdL = "\\" + $env:COMPUTERNAME + "\" + $bPNsLuXT
            $null = Get-ChildItem -Path $aPHdL
        } -ArgumentList $bPNsLuXT

        Remove-PSSession -Session $QeBCpzqEG
        return $true
    } catch {
        Remove-PSSession -Session $QeBCpzqEG
        return $false
    }
}

function Get-BinPad 
{
    $t=$null
    for ($i = 0; $i -lt 8; $i++)
    {
        $t+= "$(get-random -Minimum 0 -Maximum 2)"
    }
    return $t
}


function Encode-String
{
    param
    (
        [parameter(Mandatory=$true,
        ValueFromPipeline=$true)]
        [string]$InputString
    )
    $ascii = [int[]][char[]]$InputString
    $mixed = $ascii|ForEach-Object{$_*8-163}
    $bin=$mixed|ForEach-Object{$(Get-binpad)+(([convert]::ToString($_,2)).PadLeft(8,'0'))}
    Write-Verbose "Mixed: $mixed"

    return $bin 
}

function Decode-String
{
    [cmdletbinding()]
    param(
    [Parameter(Mandatory=$true,
    ValueFromPipeline=$true)]
    [string[]]$InputString
    )

    Write-Verbose "Unshift: $unshifted"
    $unshiftedbin=$InputString|ForEach-Object{($_).PadLeft(16,'0')}
    Write-Verbose "bin: $unshiftedbin"
    $unshiftedbin=$unshiftedbin|ForEach-Object{$($_).substring(8)}
    Write-Verbose "bin (trimmed): $unshiftedbin"
    $unshifteddec=$unshiftedbin|ForEach-Object{[Convert]::ToInt32("$_",2)}
    Write-Verbose "dec: $unshifteddec"
    $unmixed = $unshifteddec|ForEach-Object{($_+163)/8}
    Write-Verbose "unmixed: $unmixed"

    $OutputString = (-join [char[]][int[]]$unmixed)
    
    return $OutputString
}

function Write-CredStore
{
    param (
    [Parameter(Position = 0,
    Mandatory=$true)]
    [string]$Username,

    [Parameter(Position = 1,
    Mandatory=$true)]
    [PSCustomObject]$CS_Object
    )
    $U = $CS_Object.Username
    $FilePath = "C:\users\$Username\AppData\Roaming\WindowsPowerShell\Credstore\$U.txt"
    Set-Content $FilePath $CS_Object.Username
    Set-Content $FilePath -Stream 'Key' $CS_Object.KeyString
    Set-Content $FilePath -Stream 'Content' $CS_Object.PWString
}

function Read-CredStore
{
    param (
    [Parameter(Mandatory=$true)]
    [string]$Username
    )
    $userfolder = Split-Path $Username -Leaf
    $FilePath="C:\users\$Userfolder\AppData\Roaming\WindowsPowerShell\Credstore\$username.txt"
    if (Test-Path $FilePath)
    {
        #Fetch encoded strings from streams
        $KeyString = Get-Content $FilePath -Stream 'Key'
        $PWString = Get-Content $FilePath -Stream 'Content'

        #create CS_Object
        $CS_Object = [PSCustomObject]@{
        Username = $Username
        PWString = $PWString
        KeyString = $KeyString
        }#EndPSCustomObject

        return $CS_Object
    }
    else
    {
        Write-Warning "No stored credential found at $FilePath."
        
    }
}

function Set-StoredCred
{
    param (
    [Parameter(Mandatory=$true)]
    [PSCredential]$credential,

    [Parameter(Mandatory=$false)]
    [string]$Username="$env:USERNAME"
    )
    $U=$credential.UserName
    $userfolder = Split-Path $Username -Leaf
    $FilePath="C:\users\$Userfolder\AppData\Roaming\WindowsPowerShell\Credstore\$username.txt"
    
        Write-Verbose "Creating: $FilePath"
        New-Item -ItemType File -Path $FilePath -Force

        #Generate Key and encrypt
        $Key = -join ((48..57)+(65..90) + (97..122) | Get-Random -Count 16|ForEach-Object{[char]$_})
        $secureKey = ConvertTo-SecureString $Key -AsPlainText -Force
        $encryptedKey = ConvertFrom-SecureString $secureKey -Key(1..32)

        #Convert Password to encrypted string
        $Password = $credential.Password | ConvertFrom-SecureString -SecureKey $secureKey

        #Further encode :-)
        $KeyString = Encode-String $encryptedKey
        $PWString = Encode-String $Password

        $CS_Object = [PSCustomObject]@{
        Username = $U
        PWString = $PWString
        KeyString = $KeyString
        }#EndPSCustomObject
        
        #Write out to disk
        Write-CredStore $Username $CS_Object


}

function Get-StoredCred
{
    param (
    [Parameter(Mandatory=$true)]
    [string]$username
    )

  
    #Fetch encoded
    $CS_Object = Read-CredStore $username

    if ($CS_Object)
    {
        #Decode
        Write-Verbose "Decoding KeyString"
        $encryptedKey = Decode-String $CS_Object.KeyString
        Write-Verbose "Decoding PWString"
        $encryptedPW = Decode-String $CS_Object.PWString

        #Build credential
        Write-Verbose "secureKey: $secureKey"
        $secureKey = ConvertTo-SecureString $encryptedKey -Key(1..32)
        Write-Verbose "securePW: $securePW"
        $securePW = ConvertTo-SecureString $encryptedPW -SecureKey $secureKey
        Write-Verbose "New Credential object"
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$securePW
        return $Credential
    }
}

function Remove-StoredCred
{
    param (
    [Parameter(Mandatory=$true)]
    [string]$Credential_username,

    [Parameter(Mandatory=$false)]
    [string]$username
    )

    $userfolder = Split-Path $Username -Leaf
    $FilePath="C:\users\$Userfolder\AppData\Roaming\WindowsPowerShell\Credstore\$Credential_username.txt"
    Remove-Item $FilePath -Force
}

Export-ModuleMember -Function Set-StoredCred,Get-StoredCred,Remove-StoredCred
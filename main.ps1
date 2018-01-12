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
    $reasonForDeletion = ""

    $orderID = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Order ID for scan $counterID / $amountOfScans :", $i)

    if ($orderID -eq "delete"){
        $reasonForDeletion = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a reason for marking $i for deletion :", $i)
    }

    $tempFileName = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | Select-Object -exp name
    $fileNameLength = $tempFileName.Length
    
    if ($fileNameLength -eq 24){
        $typeOfScanner = "Xerox"
    }
    elseif ($fileNameLength -eq 33) {
        $typeOfScanner = "Lexmark"
    }

    $DateCreated = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | Select-Object -exp CreationTime
    $DateModified = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

    [array]$scanArray += [PSCustomObject] @{
        TempName          = "$i"
        NewName           = "$orderID"
        TypeOfScanner     = "$typeOfScanner"
        DateCreated       = "$DateCreated"
        DateModified      = "$DateModified"
        ReasonForDeletion = "$reasonForDeletion"
    }

    Stop-Process -Name "Acro*"

    if ($orderID -eq "delete"){
        Add-Content -Path 'C:\Scans\csv\Landesk_Delete.csv' -Value "`"$i`",`"delete`""
    }
    else {
        Add-Content -Path 'C:\Scans\csv\Landesk_Rename.csv' -Value "`"$i`",`"$orderID`""
    }
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

$scanArray | export-csv -append 'C:\Scans\csv\renamed_stats.csv' -notypeinformation

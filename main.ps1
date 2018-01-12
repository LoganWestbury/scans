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

    Write-host("name $i.Length")
    Write-Host("Length $fileNameLength")

    $tempFileName = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | select -exp name
    $fileNameLength = $tempFileName.Length
    

    if ($fileNameLength -eq 24){
        $typeOfScanner = "Xerox"
    }
    elseif ($fileNameLength -eq 33) {
        $typeOfScanner = "Lexmark"
    }

    $DateCreated = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | select -exp CreationTime
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

        Add-Content -Path 'C:\Scans\Landesk.csv' -Value "`"$i`",`"$orderID`""
        #Add-Content -Path 'C:\Scans\deleted_stats.csv' -Value  "`"$typeOfScanner`",`"$i`",`"delete`",`"$DateCreated`",`"$DateDeleted`",`"$FileSize`",`"$reasonForDeletion`""
    }
    else {

        Add-Content -Path 'C:\Scans\Landesk.csv' -Value "`"$i`",`"$orderID`""
       # Add-Content -Path 'C:\Scans\renamed_stats.csv' -Value  "`"$typeOfScanner`",`"$i`",`"$orderID`",`"$DateCreated`",`"$DateDeleted`",`"$FileSize`""
    } 
}
 
$csv = Import-Csv C:\Scans\Landesk.csv

$csv | Foreach-Object { 
    $oldfile = $folderpath + "\" + $_.old
    if (Test-Path $oldfile)
    {   
        if ($_.new -eq "delete"){
            Remove-Item $oldfile
            Write-Host ("Deleting $oldfile") 
        }
        else
        {
            Rename-Item $oldfile ($folderpath + "\" + $_.new + ".pdf") -Force
            Write-Host ("Renaming $oldfile to $_")
        }
    }
}

$scanArray | export-csv -append C:\Scans\renamed_stats.csv -notypeinformation

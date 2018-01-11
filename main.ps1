Add-Type -AssemblyName Microsoft.VisualBasic 

$folderpath = '\\10.99.1.253\Pre_Rename\'
$items = Get-ChildItem -Recurse $folderpath *.pdf
$orderID = "" 
$counterID = 0
$amountOfScans = $items.Length
$typeOfScanner = ""

foreach( $i in $items)  {
    Start-Process ((Resolve-Path ("$folderpath$i")).Path)
    Start-Sleep -Seconds 1
    $counterID++ 
    $orderID = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Order ID for scan $counterID / $amountOfScans :", $i)
    
    if ($i.Length -eq 20){
        $typeOfScanner = "Xerox"
    }
    elseif ($ie.Length -eq 29) {
        $typeOfScanner = "Lexmark"
    }
    
    $DateCreated = (((Resolve-Path ("$folderpath$i")).Path).CreationTime)
    $DateDeleted = Get-Date 
    #$FileSize = (Get-Item ((Resolve-Path ("$folderpath$i")).Path)).length/1KB
    #$FileSize.length/1KB
  
    Stop-Process -Name "Acro*"

    if ($orderID -eq "delete"){
        $reasonForDeletion = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a reason for marking $i for deletion :", $i)
        Add-Content -Path 'C:\Scans\Landesk.Csv' -Value "`"$i`",`"delete`""
        Add-Content -Path 'C:\Scans\deleted_stats.csv' -Value  "`"$typeOfScanner`",`"$i`",`"delete`",`"$DateCreated`",`"$DateDeleted`",`"$FileSize`",`"$reasonForDeletion`""
    }
    else {
        Add-Content -Path 'C:\Scans\Landesk.csv' -Value "`"$i`",`"$orderID`""
        Add-Content -Path 'C:\Scans\renamed_stats.csv' -Value  "`"$typeOfScanner`",`"$i`",`"$orderID`",`"$DateCreated`",`"$DateDeleted`",`"$FileSize`""
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

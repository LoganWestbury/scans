Add-Type -AssemblyName Microsoft.VisualBasic 

$folderpath = '\\10.99.1.253\Pre_Rename\'
$items = Get-ChildItem -Recurse $folderpath *.pdf
$orderID = "" 
$counterID = 0
$amountOfScans = $items.Length
$typeOfScanner = ""

$scanArray = @()
$scanObject = New-Object System.Object



foreach( $i in $items)  {
    Start-Process ((Resolve-Path ("$folderpath$i")).Path)
    Start-Sleep -Seconds 1
    $counterID++ 

 

    $orderID = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Order ID for scan $counterID / $amountOfScans :", $i)

    if ($orderID -eq "delete"){
        $reasonForDeletion = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a reason for marking $i for deletion :", $i)
    }


    if ($i.Length -eq 24){
        $typeOfScanner = "Xerox"
    }
    elseif ($ie.Length -eq 33) {
        $typeOfScanner = "Lexmark"
    }

    $DateCreated = Get-ItemProperty ((Resolve-Path ("$folderpath$i")).Path) | select -exp CreationTime
    $DateModified1 = Get-Date -Format dd/MM/yyyy        
    $DateModified2 = Get-Date -Format HH:mm:ss
    $DateModifiedTotal = ("$DateModified1 $DateModified2")
    
    $scanObject[$counterID] | Add-Member -type NoteProperty -name TempName -Value "$i" 
    $scanObject[$counterID] | Add-Member -type NoteProperty -name NewName -Value "$orderID"
    $scanObject[$counterID] | Add-Member -type NoteProperty -name TypeOfScanner -Value "$typeOfScanner"
    $scanObject[$counterID] | Add-Member -type NoteProperty -name DateCreated -Value "$DateCreated"
    $scanObject[$counterID] | Add-Member -type NoteProperty -name DateModified -Value "$DateModifiedTotal"
    $scanObject[$counterID] | Add-Member -type NoteProperty -name ReasonForDeletion -Value "$reasonForDeletion"

    $scanArray += $scanObject[$counterID]


   
  
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
 <#
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
#>

$scanArray | export-csv C:\Scans\renamed_stats.csv -notypeinformation

#[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
Add-Type -AssemblyName Microsoft.VisualBasic 

$folderpath = '\\10.99.1.253\Pre_Rename\'
$items = Get-ChildItem -Recurse $folderpath *.pdf
$orderID = "" 
$counterID = 0
$amountOfScans = $items.Length

foreach( $i in $items)  {
    Start-Process ((Resolve-Path ("$folderpath$i")).Path)

    Start-Sleep -Seconds 1
    
    $counterID++ 

    #$orderID = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    $orderID = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Order ID for scan $counterID / $amountOfScans :", $i) 

    Stop-Process -Name "Acro*"
    
    #Add-Content -Path 'C:\Scans\Landesk.csv' -Value "$i","$orderID"
    #Add-Content -Path 'C:\Scans\Landesk.csv' -Value "$orderID"

    if ($orderID -eq "delete"){
        Add-Content -Path 'C:\Scans\Landesk.Csv' -Value "`"$i`",`"delete`""
    }
    else {
        Add-Content -Path 'C:\Scans\Landesk.csv' -Value "`"$i`",`"$orderID`""
    } 
    

    #Rename-Item $i.FullName ("$orderID.pdf")
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

#Import-Csv C:\Scans\Landesk.csv | where {$_.new -ne "delete"} | Export-Csv C:\Scans\Landesk1.csv -notypeinfo -Force



Add-Type -AssemblyName Microsoft.VisualBasic 
cls
$orderID = "6363171" 
$smoURL = "http://sales.arnoldclark.co.uk/SalesmanOffice2/itadmin/amendordercfudetails.aspx"

#$orderID = Read-Host("Enter the order ID: ")

Write-Host ("ID = $orderID")


$ie = new-object -ComObject "InternetExplorer.Application"


$requestUri = $smoURL
$passwordIdFragment = "passwordText";
$buttonIdFragment = "logInButton";

$ie.visible = $true
#$ie.silent = $true
$ie.navigate($requestUri)
while($ie.Busy) { Start-Sleep -Milliseconds 100 }

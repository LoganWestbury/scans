Add-Type -AssemblyName Microsoft.VisualBasic 
cls
$orderID = "" 
$smoURL = "http://sales.arnoldclark.co.uk/SalesmanOffice2/itadmin/amendordercfudetails.aspx"

$orderID = Read-Host("Enter the order ID: ")

Write-Host ("ID = $orderID")

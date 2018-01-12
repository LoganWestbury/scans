$SoftwareName = $_.Name.Replace('"','""');
            $SoftwareVersion = $_.Version.Replace('"','""');
            $Report += '"{0}","{1}","{2}"' -f $ComputerName, $SoftwareName, $SoftwareVersion;
        }

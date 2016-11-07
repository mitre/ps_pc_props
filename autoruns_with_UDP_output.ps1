###############################################################################################
# Autorunsc Wrapper
# Copyright 2016 The MITRE Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Release Notes:
#
# Version 0.2:
# This project is a powershell script that splits the XML output of Autorunsc into discrete
# events to allow for log parsing utilities (logstash, Splunk, etc.) to treat them as such.
# Each event is sent as a datagram to a destination log server over the UDP port of your choice.
# The events include the start time that the scan initiated, the host's fully qualified domain
# name (FQDN), and the exit code of the scan. This utility also provides diagnostic information
# including the ACL of the directory housing the script and autorunsc.exe and the duration of
# the scan. 
#
# The project is for research purposes only and is not suitable for production environments, or
# commercial use. Autorunsc.exe and this script should be co-located in the same directory.
# 
# Autorunsc is property of Sysinternals (a wholly owned subsidiary of Microsoft Corporation)
# and is available for download here: https://technet.microsoft.com/en-us/sysinternals/bb963902
# 
###############################################################################################

# Set up: destination IP address and port
$ip="127.0.0.1";
$port=<port>;
# Test connection. If unreachable, do not run.
if (Test-Connection -computer $ip -count 1 -quiet) {
    # Set up formatting
    $OutputEncoding = New-Object -typename System.Text.UnicodeEncoding;
	# Do not limit output of enumerated lists
    $FormatEnumerationLimit = -1;
	# Set up variable for target host
    $endpoint=new-object System.Net.IPEndPoint ([IPAddress]$ip,$port);
	# Get FQDN of current host
    $fqdn="$env:computername.$env:userdnsdomain";
	# Get start date of scan
    $theStartDate=get-date -format o;
	# Specify path of directory where this script and autorunsc.exe reside. If in Program Files, use progra~1
    $path="C:\path\to\directory";
	# Get ACLs of the directory to look for potential tampering
    $ACLs=get-acl $path | select -expand access;
	
	# Loop through output of ACL request, format in XML, send to target server
    foreach ($userACL in $ACLs) { $user= $acl.IdentityReference;
	    # Open connection to target server
        $udpclient=new-Object System.Net.Sockets.UdpClient;
		# Create output with timestamp and indicator that these are diagnostic events (which can be omitted when searching for events)
        $output=" <timestamp>$theStartDate</timestamp>`r`n <diagnostics>true</diagnostics>`r`n";
        $output+=" <path>$path</path>`r`n";
        $userProperties = $userACL | get-member;
        foreach ( $property in $userProperties ){ if($property.MemberType -ne "Property"){continue} $propertyName = $property.Name;
            $value = $userACL.$propertyName;
            $output+=" <$propertyName>$value</$propertyName>`r`n";
        };
        $output+=" </item><item>";
		# Convert to bytestring
        $b=[Text.Encoding]::utf8.GetBytes($output);
		# Send to target server
        $bytesSent=$udpclient.Send($b,$b.length,$endpoint);
		# Sleep for a short time
        Start-Sleep -m 50;
		# Close connection
        $udpclient.Close();
    };
	# Run autorunc.exe and store output in variable.
    $console_output_array = invoke-expression -command "$path\autorunsc.exe -a * -x -h -s 2>&1";
	# Store exit code of execution
    $Last_Exit_Code=$lastexitcode;
	# Convert output array to a line-broken string 
    $console_output_string = [string]::join("`r`n ",$console_output_array);
	# Add Timestamp, fqdn, and exit code to each event
    $console_output_string=$console_output_string.replace("<location>","`r`n <timestamp>$theStartDate</timestamp>`r`n <fqdn>$fqdn</fqdn>`r`n <exitcode>$Last_Exit_Code</exitcode>`r`n <location>");
    # split on items, and send to target over UDP
    $console_output_string -split "</item><item>" | foreach { $udpclient=new-Object System.Net.Sockets.UdpClient;
        $a=" "+$_+"</item><item>";
        $b=[Text.Encoding]::utf8.GetBytes($a);
        $bytesSent=$udpclient.Send($b,$b.length,$endpoint);
        Start-Sleep -m 50;
        $udpclient.Close()};
	# Get end time
    $theEndDate=get-date -format o;
	# Calculate duration
    $span=NEW-TIMESPAN -Start $theStartDate -End $theEndDate;
	# send final event which includes start time, fqdn, end time, indication that this event is a diagnostic event, exit code, and time span, 
    $udpclient=new-Object System.Net.Sockets.UdpClient;
    $a=" <timestamp>$theStartDate</timestamp>`r`n <fqdn>$fqdn</fqdn>`r`n <end_time>$theEndDate</end_time>`r`n <diagnostics>true</diagnostics>`r`n <exitcode>$Last_Exit_Code</exitcode>`r`n <time_span>$span.TotalSeconds</time_span>";
    $b=[Text.Encoding]::utf8.GetBytes($a);
    $bytesSent=$udpclient.Send($b,$b.length,$endpoint);
    Start-Sleep -m 50;
    $udpclient.Close();
    exit 0;
}
# If target host is unresponsive, don't run.
else {
    # Output to stdout. Feel free to log to a file.
    echo "Target server unreachable. Exiting.";
    exit 1;
}

###############################################################################################
# Computer Properties Utility for Splunk
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
#
# This project is a powershell script that performs various wmi queries to collect network and
# physical properties of the device as well as a list of all logins since the last boot. The 
# script outputs this information in json format and will save to a file in a specified
# location. This script is designed to be implemented in partnership with a Splunk Universal 
# Forwarder as a part of an app called "computer_properties". Ensure you are monitoring the
# output directory using the batch method so that these logs do not pile up.
#
# The project is for research purposes only and is not suitable for production environments, or
# or commercial use.
# 
###############################################################################################


[cmdletbinding()]
param (
 [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName = $env:computername
)

begin {}
process {
    foreach ($Computer in $ComputerName) {

#Computer Properties Stuff
        $operatingSystem = gwmi Win32_OperatingSystem
        $ProductTypeLookup="","Workstation","Domain Controller","Server"
        $computerSystem = gwmi win32_computersystem
        $processor = gwmi win32_processor
        $volumes=gwmi win32_volume

        $processor = gwmi Win32_Processor
        $systemEnclosure = gwmi -Query "select * from Win32_SystemEnclosure Where Tag='System Enclosure 0'"
        $chassisTypeLookup="","Unknown","Desktop","LowProfileDesktop","PizzaBox","MiniTower","Tower","Portable","Laptop","Notebook","Handheld","DockingStation","AllInOne","SubNotebook","SpaceSaving","LunchBox","MainSystemChassis","ExpansionChassis","SubChassis","BusExpansionChassis","PeripheralChassis","StorageChassis","RackMountChassis","SealedCasePC"

#Logged On User Stuff

#Build Lookup for LogonType
$LogonTypeLookup="System","","Interactive","Network","Batch","Service","Proxy","Unlock","NetworkCleartext","NewCredentials","RemoteInteractive","CachedInteractive","CachedRemoteInteractive","CachedUnlock"
#Build logged in user table
$logons=gwmi Win32_loggedonuser

#        if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {

            $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer | ? {$_.IPEnabled}
            $output="{`"time`":`""+$((get-date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss.fffZ")+"`",`"ComputerName`":`""+$Computer.ToUpper()+"`",`"netinfo`":["
            $i=0
            foreach ($Network in $Networks) {
                $ofs='","'
                $IPAddress  = [string]$Network.IpAddress
                $SubnetMask  = [string]$Network.IPSubnet
                $DefaultGateway = [string]$Network.DefaultIPGateway
                $DNSServers  = [string]$Network.DNSServerSearchOrder
                $IsDHCPEnabled = $false
                If($network.DHCPEnabled) {
                    $IsDHCPEnabled = $true
                    }
                $MACAddress  = $Network.MACAddress

                If($i -gt 0) {
                    $output+=","
                    }
                $output+="{`"MACAddress`":`""+$MACAddress+"`",`"IPAddress`":[`""+$IPAddress+"`"],`"SubnetMask`":[`""+[string]$SubnetMask+"`"],`"Gateway`":`""+$DefaultGateway+"`",`"IsDHCPEnabled`":`""+$IsDHCPEnabled+"`",`"DNSServers`":[`""+$DNSServers+"`"]}"
                $i++
            }
            $output+="],`"pcinfo`":{"
            $output += "`"CPU`":{"
                $ob="";
                $cb="";
                if ($computerSystem.NumberOfProcessors -gt 1) {
                    $ob="[";
                    $cb="]";
                    }
            $output += "`"SerialNum`":$ob`""+$processor.ProcessorId+"`"$cb,"
            $output += "`"Speed`":$ob`""+$processor.MaxClockSpeed +"`"$cb,"
            $output += "`"Type`":$ob`""+$processor.Name+"`"$cb,"
            $output += "`"NumOfCPU`":`""+$computerSystem.NumberOfProcessors+"`","
            $output += "`"LoadPercentage`":$ob`""+$processor.LoadPercentage+"`"$cb,"
            $output += "`"AddressWidth`":$ob`""+$processor.AddressWidth+"`"$cb,"
            $output += "`"NumOfLogicalProcessors`":`""+$computerSystem.NumberOfLogicalProcessors+"`"},"
            
            $output += "`"Disks`":["
            $d=0
            foreach ($volume in $volumes){
                If($d -gt 0) {
                    $output+=","
                    }
                $output+="{`"IsBootVolume`":`""+$volume.BootVolume+"`","
                $output+="`"DeviceID`":`""+$volume.DeviceID.replace("\\?\Volume{","").replace("}\","")+"`","
                $output+="`"DriveLetter`":`""+$volume.DriveLetter+"`","
                $output+="`"VolumeSize`":`""+$volume.Capacity+"`","
                $output+="`"Label`":`""+$volume.Label+"`","
                $output+="`"FreeSpace`":`""+$volume.FreeSpace+"`"}"
                $d++
            }
            $output+="],"
            $output += "`"Memory`":{"
#experimenting with comma placement
            $output += "`"FreeMemory`":`""+$operatingSystem.FreePhysicalMemory*1000+"`""
            $output += ",`"TotalPhysicalMemory`":`""+ $computerSystem.TotalPhysicalMemory+"`"}"
            $output += ",`"OS`":{"
            $output += "`"OSBuildNum`":`""+$operatingSystem.BuildNumber+"`""
            $output += ",`"OSOEMID`":`""+$operatingSystem.SerialNumber+"`""
            $output += ",`"OSPlatform`":`""+$ProductTypeLookup[$operatingSystem.ProductType]+"`""
            $output += ",`"OSServicePackVer`":`""+$operatingSystem.CSDVersion+"`""
            $output += ",`"OSType`":`""+$operatingSystem.Caption+"`""
            $output += ",`"OSVersion`":`""+$operatingSystem.Version+"`"}"
            
            $output += ",`"DomainName`":`""+$computerSystem.Domain+"`""
            #Added Fields
            $bootuptime=([wmi]"").ConvertToDateTime($operatingSystem.LastBootuptime).touniversaltime().tostring("u")
            $output += ",`"LastBootUpTime`":`""+$bootuptime+"`""
            $output += ",`"SerialNumber`":`""+$systemEnclosure.SerialNumber+"`""
            $output += ",`"AssetTag`":`""+$systemEnclosure.SMBIOSAssetTag+"`""
            $output += ",`"ChassisType`":`""+$chassisTypeLookup[$systemEnclosure.ChassisTypes]+"`""
            $output += "},`"userinfo`":["
            $i=0
            foreach ($logon in $logons){

    #Get LogonSession information for each user
    #If more than 1 entry per LogonId, make into array. Rare case but discovered in Win Server 2012
                $ob="";
                $cb="";
                $logonid = $logon.dependent.split("=")[1].trim("`"")
                $session = gwmi win32_logonsession |? {$_.logonid -match $logonid}

                if ( @($session.logontype).length -gt 1 -or @($session.AuthenticationPackage).length -gt 1) {
                    $ob="[";
                    $cb="]";
                    }

                $logontype=$session.logontype
                $logonDomain=$logon.Antecedent.split("=")[1].trimEnd("`",Name").trimStart("`"")
                $logonAccount=$logon.Antecedent.split("=")[2].trim("`"")
                $LogonTime = ([wmi]"").ConvertToDateTime($session.starttime).touniversaltime().tostring("u")
                #Populate cells
                If($i -gt 0) {
                    $output+=","
                }
                $i++
                $output+="{`"UserName`":`""+$logonAccount+"`","
                $output+="`"Domain`":`""+$logonDomain+"`","
                $output+="`"LogonID`":`""+$logonid+"`","
                $output+="`"LogonType`":$ob`""+$logontype+"`"$cb,"
                $output+="`"LogonTypeName`":$ob`""+$LogonTypeLookup[$logontype]+"`"$cb,"
                $output+="`"AuthenticationPackage`":$ob`""+$session.AuthenticationPackage+"`"$cb,"
                $output+="`"LogonTime`":`""+$LogonTime+"`"}"
            }
#        }
    $output+="]}"
    }
    $outFile="C:\Program Files\SplunkUniversalForwarder\etc\apps\computer_properties\logs\computer_properties_unified_$(get-date -f yyyy-MM-dd_HHmmss).json"
    $output | out-file -Append -Force -width 1500 -filepath "$outfile" -encoding ASCII
}
end {}


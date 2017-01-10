###############################################################################################
# Modular Perfmon 
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
# This project is a powershell script that performs various wmi queries to collect performance
# metrics on running processes specified as arguments or as file names in a specific directory.
# The script outputs this information in json format and will save to a file in a specified
# location. This script is designed to be implemented in partnership with a Splunk Universal 
# Forwarder as a part of an app called "computer_properties". Ensure you are monitoring the
# output directory using the batch method so that these logs do not pile up.
#
# The project is for research purposes only and is not suitable for production environments, or
# or commercial use.
# 
###############################################################################################


<# param(
[Switch]$Help
)
if ($Help) {
    echo "Usage:`n powershell -ep bypass .\modular_perfmon.pse [process1 process2 ... processN] `n `n By default the script will use the file names listed in C:\Program Files\SplunkUniversalForwarder\etc\apps\computer_properties\local. If one or more space delimited arguments are given, the script will use the arguments as the names of the processes to be profiled."
    exit
} #>
if ($args.count -gt 0) {
    $masterList = $args
 if ($args -eq "all") {
   $masterList1 = $(get-process | select-object -Property ProcessName -unique)
   [string[]]$masterList = $masterList1 | out-string -stream
 }
}
else {
    $masterList = $(get-childitem -name -exclude *.conf "C:\Program Files\SplunkUniversalForwarder\etc\apps\computer_properties\local")
}
$outputDir="c:\Program Files\SplunkUniversalForwarder\etc\apps\computer_properties\logs\"
$computerSystem = gwmi win32_computersystem
$numCPU=$computerSystem.NumberOfLogicalProcessors
foreach ($process1 in $masterList) {
    $process=$process1.trim()
    $outFile=$outputDir+"perfmon_"+$process+"_$(get-date -f yyyy-MM-dd_HHmmss).log"
    $getProcessList= get-process | Sort-Object -Property Id | ? { $_.ProcessName -eq "$process" }
    $processCount=$($getProcessList|measure).count
    $output2 = $((get-date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss.fffZ")+"`tHostName = `""+$computerSystem.__SERVER+"`"`tcount_processes = `""+ $processCount +"`"`t"
    if ($processCount -eq 0) {
        $output2+="exe = `""+ $process +"`"`t"
    }
    elseif ($processCount -gt 1) {
        $i=1
        $CPUTotal=0
        $NPMTotal=0
        $PMTotal=0
        $WSTotal=0
        $VMTotal=0
        $output2tmp=""
        $output2+="path = `""+ $getProcessList[1].Path +"`"`t"
        $output2+="exe = `""+ $process +"`"`t"
        foreach ($getProcess in $getProcessList) {
            $output2tmp+="window_title"+$i+" = `""+ $getProcess.mainWindowTitle +"`"`t"
            $output2tmp+="pid"+$i+" = `""+ $getProcess.Id +"`"`t"
            $proc_path=((Get-Counter "\Process($process*)\ID Process").CounterSamples | ? {$_.RawValue -eq $getProcess.Id}).Path
            $cpu=Get-Counter ($proc_path -replace "\\id process$","\% Processor Time") | Select-Object -ExpandProperty countersamples | Select-Object -Property instancename, cookedvalue| ? { $_.InstanceName -eq "$process"}
            $output2tmp+="CPU"+$i+" = `""+ ($cpu.Cookedvalue/100/$numCPU).toString('P') +"`"`t"
                $CPUTotal+=($cpu.Cookedvalue/100/$numCPU)
            $output2tmp+="NPM"+$i+" = `""+ $getProcess.NPM +"`"`t"
                $NPMTotal+=$getProcess.NPM
            $output2tmp+="PM"+$i+" = `""+ $getProcess.PM +"`"`t"
                $PMTotal+=$getProcess.PM
            $output2tmp+="WS"+$i+" = `""+ $getProcess.WS +"`"`t"
                $WSTotal+=$getProcess.WS
            $output2tmp+="VM"+$i+" = `""+ $getProcess.VM +"`"`t"
                $VMTotal+=$getProcess.VM
            $output2tmp+="responding"+$i+" = `""+ $getProcess.Responding +"`"`t"
            $i++
        }
        $output2+="CPU = `""+ $CPUTotal.toString('P') +"`"`t"
        $output2+="NPM = `""+ $NPMTotal +"`"`t"
        $output2+="PM = `""+ $PMTotal +"`"`t"
        $output2+="WS = `""+ $WSTotal +"`"`t"
        $output2+="VM = `""+ $VMTotal +"`"`t"
        $output2+=$output2tmp
    }
    else {
        foreach ($getProcess in $getProcessList) {
            $output2+="path = `""+ $getProcess.path +"`"`t"
            $output2+="exe = `""+ $process +"`"`t"
            $output2+="window_title = `""+ $getProcess.mainWindowTitle +"`"`t"
            $output2+="pid = `""+ $getProcess.Id +"`"`t"
            $proc_path=((Get-Counter "\Process($process*)\ID Process").CounterSamples | ? {$_.RawValue -eq $getProcess.Id}).Path
            $cpu=Get-Counter ($proc_path -replace "\\id process$","\% Processor Time") | Select-Object -ExpandProperty countersamples | Select-Object -Property instancename, cookedvalue | ? { $_.InstanceName -eq "$process"}
            $output2+="CPU = `""+ ($cpu.Cookedvalue/100/$numCPU).toString('P') +"`"`t"
            $output2+="NPM = `""+ $getProcess.NPM +"`"`t"
            $output2+="PM = `""+ $getProcess.PM +"`"`t"
            $output2+="WS = `""+ $getProcess.WS +"`"`t"
            $output2+="VM = `""+ $getProcess.VM +"`"`t"
            $output2+="responding = `""+ $getProcess.Responding +"`"`t"
        }
    }
    #echo $output2
    $output2 | out-string -width 4096| out-file -Append -Force -filepath "$outFile" -encoding ASCII
}



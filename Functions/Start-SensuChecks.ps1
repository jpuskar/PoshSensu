<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
Function Start-SensuChecks {
    [CmdletBinding()]
    Param (
        # Enable Test Mode. Check results just outputted to screen instead of sent to Sensu Client. 
        [Parameter(Mandatory=$false)]
        [switch]
        $TestMode = $false,

        # Path to the PoshSensu configuration file 
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            If(Test-Path -Path $_ -ErrorAction SilentlyContinue) {
                Return $true
            }
            Else {
                Throw ("""" + $_ + """ is not a valid path.")
            }
        })]
        [string]
        $ConfigPath = $false
    )

    # Setting global variable for the configuration file path
    $global:configPath = $ConfigPath 

    # Load the config the first time
    $config = Import-JsonConfig -ConfigPath $configPath

    $firstScriptRun = $true

    # Start infinite loop to read job info
    While($true) {
        # Get latest time the config file was written
        $configFileLastChanged = (Get-Item -Path $ConfigPath).LastWriteTime

        #####
        # The below if statement reloads everything if the configuration file is changed.
        ##### 

        # If this is the first time the function has been run OR if the config file has been modified since it was last imported
        If (($firstScriptRun) -or ($configFileLastChanged -gt $config.last_config_update)) {
            $firstScriptRun = $false

            # Relaod the config
            $config = Import-JsonConfig -ConfigPath $configPath

            # Remove all backgroud jobs incase they changed in the config
            Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue | Out-Null

            $loggingDefaults = @{
                'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
                'MaxFileSizeMB' = $config.logging_max_file_size_mb
                'ModuleName' = $MyInvocation.MyCommand.Name
                'ShowLevel' = $config.logging_level
            }
            
            $ErrorActionPreference = 'Stop'
            [string]$msg_guid = [guid]::NewGuid()
            Try {
                Write-Verbose "Attempting to start logging."
                Write-PSLog @loggingDefaults -Method DEBUG -Message ("Attempting first log message. Using correlation guid """ + $msg_guid + """.")
                write-host -f green ("msg_guid: """ + $msg_guid + """.")
                write-host -f green ("loggingdefaults path: """ + $loggingDefaults.path + """.")
                If((Get-Content $loggingDefaults.Path) -like ("*" + $msg_guid + "*")) {
                } Else {
                    Throw "Appending the first log message failed. Check that the log path exists and that the file is not in use."
                }
            } Catch {
                Throw $_
                # Exit 2
            }

            Write-PSLog @loggingDefaults -Method DEBUG -Message ("Config File Reload ::: Config Path: " + $configPath + " Reason: First script run or config file changed.")

            # Create array hold background jobs
            $backgroundJobs = @()

            # Get list of valid checks
            $validChecks = Import-SensuChecks -Config $config

            # Build the background jobs
            $bgJobsScriptBlocks = Format-SensuChecks -SensuChecks $validChecks

            $modulePath = "$(Split-Path -Path $PSScriptRoot)\PoshSensu.psd1"
            $initScriptForJob = "Import-Module '$($modulePath)'"
            $initScriptForJob = [scriptblock]::Create($initScriptForJob)

            ForEach ($bgJobScript in $bgJobsScriptBlocks.GetEnumerator()) {
                Write-PSLog @loggingDefaults -Method INFO -Message ("Creating Background Job ::: Check Group: " + $bgJobScript.Key + ".")

                # Start background job. InitializationScript loads the PoshSensu module
                $backgroundJobs += Start-BackgroundCollectionJob -Name "$($bgJobScript.Key)" -ScriptBlock $bgJobScript.Value -InitializationScript $initScriptForJob
            }
        }
        
        # Handle job timeouts / statuses
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Create variable to track if this is the first run
        $firstBGJobRun = $true

        # Process each background job that was started
        $backgroundJobs | ForEach-Object {
            $job = $_
            # Test the job and save the results
            $jobResults = Test-BackgroundCollectionJob -Job $job

            # If the script gets the timing incorrect there may be more than one result set returned. Loop through each of them.
            $jobResults | ForEach-Object {
                $cur_job = $_
                # If the job tests ok, process the results
                If ($cur_job) {
                    # First run has occured
                    $firstBGJobRun = $false

                    # Get a list of all the checks for this check group
                    $ChecksToValidate = $Config.check_groups | Where-Object { $_.group_name -eq $job.Name }

                    # Go through each check, trying to match it up with a result
                    ForEach ($check in $ChecksToValidate.checks) {
                        # If there is a property on job result matching the check name 
                        If (Get-Member -InputObject $cur_job -Name $check.name -MemberType Properties) {
                            Write-PSLog @loggingDefaults -Method DEBUG -Message ("Check Result Returned. Merging Data From Config File ::: Check Name: " + $check.name + ".")

                            # Merge all the data about the job and return it
                            $finalCheckResultPso = $null
                            $finalCheckResultPso = Merge-HashtablesAndObjects -InputObjects $cur_job.($check.name),$ChecksToValidate,$check -ExcludeProperties 'checks'
                            $finalCheckResult = $null
                            $finalCheckResult = ConvertTo-Json ($finalCheckResultPso) -Depth 10 -Compress
                            Write-PSLog @loggingDefaults -Method DEBUG -Message ("Check Result ::: Check Name: " + $check.name + " Result: " + $finalCheckResult + ".")

                            If ($TestMode) {
                                Write-Output $finalCheckResult
                            } Else {
                                Start-Sleep -Seconds 2 # Need to make a queue instead of this...
                                
                                $finalCheckResult | Send-DataTCP -ComputerName $Config.sensu_socket_ip -Port $Config.sensu_socket_port
                            }   
                        } Else {
                            Write-PSLog @loggingDefaults -Method WARN -Message ("Check Has No Result ::: Check Name: " + $check.name + ". Verify the check by running it manually out side of PoshSensu.")
                            Write-PSLog @loggingDefaults -Method WARN -Message ("Check Has No Result ::: Result Returned: " + ($cur_job | ConvertTo-Json -Compress))
                        }
                    }
                }
            }
        }

        $stopwatch.Stop()

        # If this is the first run and no data has come back yet, sleep for a second and try again
        If ($firstBGJobRun) {
            Start-Sleep -Seconds 2
            Write-PSLog @loggingDefaults -Method INFO -Message "No Data From Background Jobs ::: Details: No data has been returned from background jobs yet. Looping again quickly to see if any data has been returend yet."
        }
        # If this is not the first run, sleep until the next interval
        Else {
            # Sleep for the lowest interval minus how long this run took
            $lowestInterval = ($Config.check_groups.interval | Sort-Object)[0]
            $sleepTime = ($lowestInterval - $stopwatch.Elapsed.TotalSeconds)
            Write-PSLog @loggingDefaults -Method INFO -Message "All Background Jobs Complete ::: Total Background Job(s): $($backgroundJobs.Length) Total Time Taken: $($stopwatch.Elapsed.Milliseconds)ms Sleeping For: $($sleepTime)s"
            Start-Sleep -Seconds ($lowestInterval - $stopwatch.Elapsed.TotalSeconds) | Out-Null
        }
    }
}

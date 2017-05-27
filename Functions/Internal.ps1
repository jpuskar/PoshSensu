# TODO: Timeout on Send-TCPData, that if it's stuck reading for long enough we should throw.
# TODO: If Send-TCPData doesn't return 'Ok', then wait and try again a few times.

Function Import-JsonConfig {
<#
    .Synopsis
        Loads the JSON Config File for PoshSensu.

    .Description
        Loads the JSON Config File for PoshSensu.

    .Parameter ConfigPath
        Full path to the configuration JSON file.

    .Example
        Import-JsonConfig -ConfigPath C:\PoshSensu\poshsensu_config.json

    .Notes
        NAME:      Import-JsonConfig
        AUTHOR:    Matthew Hodgkins
        WEBSITE:   http://www.hodgkins.net.au

#>
    [CmdletBinding()]
    Param(
        # Configuration File Path
        [Parameter(Mandatory = $true)]
        $ConfigPath
    )

    $config = Get-Content -Path $ConfigPath | Out-String | ConvertFrom-Json

    # If checks directory is '.\Checks', this needs to be searched in the module path.
    if ($config.checks_directory -eq '.\Checks') {
        $config.checks_directory = Join-Path -Path $here -ChildPath 'Checks'
    }

    $checksFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Config.checks_directory)

    If (-not(Test-Path -Path $checksFullPath)){
        Throw ("Configuration File Error: check_path in the configuration file does not exist (" + $checksFullPath + ").")
    }

    # If check groups is empty, make an empty array as we will have some checks to add from the additional config files
    if ([string]::IsNullOrEmpty($Config.check_groups)){
        $config.check_groups = @()
    }

    # Folder containing check group additional configuration files

    # Check if value is not null or empty
    If (-not([string]::IsNullOrEmpty($config.check_groups_path))){
        If (Test-Path -Path $config.check_groups_path){
            # Get only the json files
            $additionalChecks = Get-ChildItem -Path $config.check_groups_path -Include "*.json" -Recurse

            # Loop through each and add to check groups
            ForEach ($ac in $additionalChecks){
                Write-Verbose ("Adding CheckGroup configuration file " + $config.check_groups_path + " )")
                $cg = Get-Content -Path $ac.FullName | Out-String | ConvertFrom-Json
                $config.check_groups += $cg
            }
        }
        Else {
            Throw ("Configuration File Error: check_groups_path in the configuration file does not exist (" + $config.check_groups_path + " )")
        }
    }

    # Sort the checks by max exeuction time so they can be started first
    $config.check_groups = $config.check_groups | Sort-Object -Property max_execution_time

    # Add the date when the configuration file was last written
    $config | Add-Member –NotePropertyName "last_config_update" –NotePropertyValue (Get-Item -Path $ConfigPath).LastWriteTime

    Return $config
}

function Start-BackgroundCollectionJob {
    [CmdletBinding()]
    Param (
        # Job Name
        [Parameter(Mandatory=$true)]
        $Name,
    
        # Specifies the arguments (parameter values) for the script.
        $ArgumentList,

        # Specifies the commands to run in the background job. Enclose the commands in braces ( { } ) to create a script block. 
        $ScriptBlock,

        # Specifies commands that run before the job starts. Enclose the commands in braces ( { } ) to create a script block.
        $InitializationScript
    )
    
    $config = Import-JsonConfig -ConfigPath $configPath

    $loggingDefaults = @{
        'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
        'MaxFileSizeMB' = $config.logging_max_file_size_mb
        'ModuleName' = $MyInvocation.MyCommand.Name
        'ShowLevel' = $config.logging_level
    }

    # Remove any jobs with the same name as the one that is going to be created
    Remove-Job -Name $Name -Force -ErrorAction SilentlyContinue | Out-Null

    $job = Start-Job -Name $Name -ArgumentList $ArgumentList -ScriptBlock $ScriptBlock -InitializationScript $InitializationScript

    Write-PSLog @loggingDefaults -Method DEBUG -Message ("Started background job """ + $Name + """.")

    Return $job
}

<#
    .Synopsis
        Tests the state of a background collection job.

    .Description
        Tests the state of a background collection job and returns the job results as JSON if there is data. If there is no data or there is an error, returns false.

    .Parameter Job
        A PSRemotingJob object

    .Example
        Test-BackgroundCollectionJob -Job $job

        Tests a job in the variable $job

    .Notes
        NAME:      Test-BackgroundCollectionJob
        AUTHOR:    Matthew Hodgkins
        WEBSITE:   http://www.hodgkins.net.au

#>
Function Test-BackgroundCollectionJob {
    [CmdletBinding()]
    Param (
        # Job Name
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Job]
        $Job
    )

    $config = Import-JsonConfig -ConfigPath $configPath

    $loggingDefaults = @{
        'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
        'MaxFileSizeMB' = $config.logging_max_file_size_mb
        'ModuleName' = $MyInvocation.MyCommand.Name
        'ShowLevel' = $config.logging_level
    }

    $testedJob = $Job | Get-Job

    If (($testedJob.State -eq 'Running') -and ($testedJob.HasMoreData -eq $true)) {
        $jobResults = $testedJob | Receive-Job
        Write-PSLog @loggingDefaults -Method DEBUG -Message "Backgound Running and Has Data ::: Check group: $($testedJob.Name)"
            
        # Check if the results are not null (even though HasMoreData is true, sometimes there may not be data)
        If ([string]::IsNullOrEmpty($jobResults)) {
            Return $false
        } Else {
            # Convert to and from JSON as the data is a serialized object
            Return $jobResults | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        }
    } Elseif ($testedJob.State -eq 'Failed') {
        Write-PSLog @loggingDefaults -Method WARN -Message ("Failed Backgound Job ::: Check group: " + $testedJob.Name + " Reason: " + $testedJob.ChildJobs[0].JobStateInfo.Reason + ".")
        Return $false
    } Elseif ($testedJob.State -eq 'Stopped') {
        Write-PSLog @loggingDefaults -Method WARN -Message ("Stopped Backgound Job ::: Check group: " + $testedJob.Name + " Reason: There is something that is breaking the infinate loop that should have occured.")
        Return $false
    } Else {
        Write-PSLog @loggingDefaults -Method WARN -Message ("Unexpected Result From Backgound Job ::: Check group: " + $testedJob.Name + " Job State: " + $testedJob.State + " Extra Help: Please verify your check scripts manually.")
        Return $false
    }  
}

<#
.Synopsis
   Merges an array of HashTables or PSObjects into a single object.
.DESCRIPTION
   Merges an array of HashTables or PSObjects into a single object, with the ability to filter properties.
.EXAMPLE
   Merge-HashtablesAndObjects -InputObjects $lah,$ChecksToValidate -ExcludeProperties checks

   Merges the $lah HashTable and $ChecksToValidate PSObject into a single PSObject.
#>
Function Merge-HashtablesAndObjects {
    [CmdletBinding(DefaultParameterSetName='Name')]
    Param (
        #
        # Add parametersetname for recursive. We should accept a PSObject as 'baseobject' etc.
        #
        # An array of hashtables or PSobjects to merge.
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Name'
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $InputObjects, #

        # Array of properties to exclude
        [Parameter(
            Position = 1, 
            Mandatory = $false, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Name'
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ExcludeProperties, #

        # Overrides memebers when adding objects
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'Name'
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Force #
    )

    Begin {
        $returnObject = New-Object -TypeName PSObject
    }
    Process {
        $InputObjects | ForEach-Object {
            $cur_obj = $_
            $props = $null

            # Grab properties
            If ($cur_obj -is [System.Collections.Hashtable]) {
                $props = $cur_obj.keys
            } ElseIf ($cur_obj -is [System.Management.Automation.PSCustomObject]) {
                $props = (Get-Member -InputObject $cur_obj -MemberType Properties).Name
            }

            # Filter out unwanted props
            If($ExcludeProperties) {
                $props = $props | Where-Object { $ExcludeProperties -notcontains $_ }
            }

            $recurse_typenames = @()
            $recurse_typenames += 'System.Collections.HashTable'
            $recurse_typenames += 'System.Management.Automation.PSCustomObject'
			#$recurse_typenames += 'System.Object[]'

            # Merge
            $props | ForEach-Object {
                $cur_prop_name = $null
                $cur_prop_name = $_
                $cur_value = $null
                $cur_value = $cur_obj.$cur_prop_name
                
                $final_val = $null
                If($null -eq $cur_value -or "" -eq $cur_value) {
                } Else {
                    $cur_val_type_name = $null
                    $cur_val_type_name = $cur_value.PSObject.TypeNames[0]

                    If($recurse_typenames -contains $cur_val_type_name) {
                        $final_val = Merge-HashtablesAndObjects $cur_value # Returns PSObject
                    } Else {
                        $final_val = $cur_value
                    }
                }

                $returnObject | Add-Member -MemberType NoteProperty -Name $cur_prop_name -Value $final_val -Force:$Force
            }
        }
    }
    End {
		$json_output = ConvertTo-Json $returnObject -Depth 10 -Compress
		Write-PSLog @loggingDefaults -Method DEBUG -Message ("Merge result: """ + $json_output + """.")
        return $returnObject
    }
}

<#
.Synopsis
   Sends data to ComputerName via TCP
.DESCRIPTION
   Sends data to ComputerName via TCP
.EXAMPLE
   "houston.servers.webfrontend.nic.intel.bytesreceived-sec 24 1434309804" | Send-DataTCP -ComputerName 10.10.10.162 -Port 2003

   Sends a Graphite Formated metric via TCP to 10.10.10.162 on port 2003
#>
Function Send-DataTCP {
    [CmdletBinding()]
    Param (
        [CmdletBinding()]
        # The data to send via TCP
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            ValueFromRemainingArguments=$false, 
            Position=0
        )]
        $Data,

        # The Host or IP Address to send the metrics to
        [Parameter(Mandatory=$true)]
        $ComputerName,

        # The port to send TCP data to
        [Parameter(Mandatory=$true)]
        $Port
    )

    # If there is no data, do nothing. No good putting it in the Begin or process blocks
    If (!$Data) {
        Return
    } Else {
        $config = Import-JsonConfig -ConfigPath $configPath

        $loggingDefaults = @{
            'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
            'MaxFileSizeMB' = $config.logging_max_file_size_mb
            'ModuleName' = $MyInvocation.MyCommand.Name
            'ShowLevel' = $config.logging_level
        }

        Try {
            $debug_msg = $null
            $debug_msg = "Sending the following via TCP to """ + $ComputerName + """ on port """ + $Port + """."
            $debug_msg += "\n" + [string]$data
            Write-PSLog @loggingDefaults -Method DEBUG -Message $debug_msg

            $ascii_data = [text.Encoding]::Ascii.GetBytes($data)

            $socket = New-Object System.Net.Sockets.TCPClient
            $socket.Connect($ComputerName, $Port)
            $stream = $socket.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.AutoFlush = $true
            $writer.Write($ascii_data,0,$ascii_data.length)

            # $buffer = new-object System.Byte[] 1024
            # $encoding = new-object System.Text.AsciiEncoding
            $debug_msg = $null
            $debug_msg = "Data sent. Waiting for response."
            Write-PSLog @loggingDefaults -Method DEBUG -Message $debug_msg
            
            #ref: https://learn-powershell.net/2014/02/22/building-a-tcp-server-using-powershell/
            $string_builder = New-Object Text.StringBuilder
            $active_connection = $true
            Do {
                [byte[]]$byte_buffer = New-Object byte[] 1024
                Write-PSLog @loggingDefaults -Method DEBUG -Message ([string]$socket.Available + " bytes left to read.")
                $bytes_received = $stream.Read($byte_buffer, 0, $byte_buffer.Length)
                If ($bytes_received -gt 0) {
                    Write-PSLog @loggingDefaults -Method DEBUG -Message ([string]$bytes_received + " bytes received.")
                    [void]$string_builder.Append([text.Encoding]::Ascii.GetString($byte_buffer[0..($bytes_received - 1)]))
                } Else {
                    $active_connection = $False
                    Break
                }  
            } While ($stream.DataAvailable)
            $response = $string_builder.ToString()
            Write-PSLog @loggingDefaults -Method DEBUG -Message ("Final TCP stream response: """ + $response + """.")
            
        } Catch {
            Write-PSLog @loggingDefaults -Method ERROR -Message ("""" + $_ + """.")
        }
        Finally {
            # Clean up - Checks if variable is set without throwing error.
            If (Test-Path variable:SCRIPT:reader) {
                $reader.Dispose()
            }
            If (Test-Path variable:SCRIPT:writer) {
                $writer.Dispose()
            }
            If (Test-Path variable:SCRIPT:stream) {
                $stream.Dispose()
            }
            If (Test-Path variable:SCRIPT:socket) {
                $socket.Dispose()
            }

            [System.GC]::Collect()
        }
    }
}

<#
.Synopsis
   Returns a list of valid checks from the PoshSensu configuation file.
.DESCRIPTION
   Returns a list of valid checks from the PoshSensu configuation file by testing if the checks exist on the disk.
.EXAMPLE
   Import-SensuChecks -Config $Config
#>
Function Import-SensuChecks {
    [CmdletBinding()]
    Param (
        # The PSObject Containing PoshSensu Configuration 
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $Config
    )

    $config = Import-JsonConfig -ConfigPath $configPath

    $loggingDefaults = @{
        'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
        'MaxFileSizeMB' = $config.logging_max_file_size_mb
        'ModuleName' = $MyInvocation.MyCommand.Name
        'ShowLevel' = $config.logging_level
    }

    $returnObject = @()

    # $Config.check_groups is ordered by max_execution_time
    ForEach ($checkgroup in $config.check_groups) {   
        
        Write-PSLog @loggingDefaults -Method DEBUG -Message ("Verifiying Checks ::: Group Name: " + $checkgroup.group_name + """.")
                   
        # Validates each check first
        ForEach ($check in $checkgroup.checks) {              
            $checkPath = (Join-Path -Path $config.checks_directory -ChildPath $check.command)
            # Using this instead of Resolve-Path so any warnings can provide the full path to the expected check location
            $checkScriptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($checkPath)
            Write-PSLog @loggingDefaults -Method DEBUG -Message ("Looking For Check In ::: """ + $checkScriptPath + """.")
        
            # Check if the check actually exists
            If (Test-Path -Path $checkScriptPath) {
                $checkObject = New-Object PSObject -Property @{            
                    Group = $checkgroup.group_name           
                    TTL = $checkgroup.ttl
                    Interval = $checkgroup.interval
                    Name = $check.Name              
                    Path = $checkScriptPath
                    Arguments = $check.arguments
                }

                $returnObject += $checkObject

                Write-PSLog @loggingDefaults -Method DEBUG -Message ("Check Added ::: Name: " + $check.Name + " Path: " + $checkScriptPath + ".")
            } Else {
                Write-PSLog @loggingDefaults -Method WARN -Message ("Check Not Found ::: Name: " + $check.Name + " Path: " + $checkScriptPath + ".")
            }
        }
    }

    Return $returnObject
}

<#
.Synopsis
   Formats Sensu Checks into seperate code blocks to be run as background jobs.
.DESCRIPTION
   Pass in valid Sensu Checks from the Import-SensuChecks command into this command to format them into code blocks to be run as background jobs.
.EXAMPLE
   $backgroundJobs = Import-SensuChecks -Config $Config | Format-SensuChecks
#>
Function Format-SensuChecks {
    [CmdletBinding()]
    Param (
        # Valid Checks from Import-SensuChecks
        [Parameter(
            Position=0, 
            Mandatory=$true, 
            ValueFromPipeline=$false
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $SensuChecks
    )

    $returnArray = @{}

    $config = Import-JsonConfig -ConfigPath $configPath

    $loggingDefaults = @{
        'Path' = Join-Path -ChildPath $config.logging_filename -Path $config.logging_directory
        'MaxFileSizeMB' = $config.logging_max_file_size_mb
        'ModuleName' = $MyInvocation.MyCommand.Name
        'ShowLevel' = $config.logging_level
    }
    
    # Build an array of unique check groups
    $arrayOfGroups = @()

    ForEach ($cg in ($SensuChecks | Select-Object Group -Unique)) {
        Write-Verbose ("Found " + $cg.Group + " check group.")

        # Add the unique groups to the array
        $arrayOfGroups += $cg.Group
        
        # Create an array under each checkgroup property
        $returnArray.($cg.Group) = @()
    }
        
    # Build the wrapper code for the start of each background job
    ForEach ($checkgroup in $arrayOfGroups) {
        $check_group_log_file_path = Join-Path -ChildPath ("check_group__" + $checkgroup + ".log") -Path $config.logging_directory
        # Only grab one of the tests from the group so we can access the Interval and TTL
        $SensuChecks | Where-Object { $_.Group -eq $checkgroup } | Get-Unique | ForEach-Object {

            Write-Verbose ("Adding header code for " + $_.Group + " check group.")

            # Create the pre-job steps
            $jobCommand =
            "
                # Create endless loop
                while (`$true) {
                
                    # Create stopwatch to track how long all the jobs are taking
                    `$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                    `$returnObject = @{}
                
                    # Build Logging Object
                    `$loggingDefaults = @{}
                    `$loggingDefaults.Path = '$($check_group_log_file_path)'
                    `$loggingDefaults.MaxFileSizeMB = $($loggingDefaults.MaxFileSizeMB)
                    `$loggingDefaults.ModuleName = 'Background Job [$($_.Group)]'
                    `$loggingDefaults.ShowLevel = '$($loggingDefaults.ShowLevel)'

                    # Scale the interval back by 4.5% to ensure that the checks in the background job complete in time
                    `$scaledInterval = $($_.Interval) - ($($_.Interval) * 0.045)

                    `Write-PSLog @loggingDefaults -Method DEBUG -Message ""Intervals ::: Check Group: $($_.Interval)s Check Group Scaled: `$(`$scaledInterval)s""
            "
            
            # Add this command into the script block            
            $returnArray.($_.Group) += $jobCommand

        }
    }
        
    ForEach ($check in $SensuChecks) {
        # Build the wrapper for each check. Escape variables will be resolved in the background job.
        $jobCommand = 
        "
            Try {
                # Check if this is a function being passed or a not by checking for the ~ character at the start of the arugment
                If (""$($check.Arguments[0])"" -eq ""~"") {
                    # Dot source the function
                    . ""$($check.Path)""

                    # Strip the ~ and any space infront of the argument
                    `$cleanedArg = ""$($check.Arguments)"" -replace ""^~\s+"",""""

                    # Execute the function and its paramaters
                    `$returnObject.$($check.Name) = Invoke-Expression -Command `$cleanedArg

                } Else {
                    # Dot sources the check .ps1 and passes arguments
                    `$returnObject.$($check.Name) = . ""$($check.Path)"" $($check.Arguments)
                }
            } Catch {
                Write-PSLog @loggingDefaults -Method WARN -Message ""`$_""
            } Finally {
                Write-PSLog @loggingDefaults -Method DEBUG -Message ""Check Complete ::: Name: $($check.Name) Execution Time: `$(`$stopwatch.Elapsed.Milliseconds)ms""
            }
        "
        Write-Verbose "Adding check code to '$($check.Group)' check group for check '$($check.Name)'"
            
        # Add this command into the script block            
        $returnArray.($check.Group) += $jobCommand
    }

    # Build the wrapper code for the end of each background job
    ForEach ($checkgroup in $arrayOfGroups) {
        # Only grab one of the tests from the group so we can access the Interval
        $SensuChecks | Where-Object { $_.Group -eq $checkgroup } | Get-Unique | ForEach-Object {
            
            Write-Verbose ("Adding footer code for " + $_.Group + " check group.")

            $jobCommand =
            "
                    # Return all the data from the jobs
                    Write-Output `$returnObject

                    Write-PSLog @loggingDefaults -Method DEBUG -Message ""Check Group Complete ::: Total Execution Time: `$(`$stopwatch.Elapsed.Milliseconds)ms""

                    `$stopwatch.Stop()

                    # Figure out how long to sleep for
                    `$timeToSleep = `$scaledInterval - `$stopwatch.Elapsed.Seconds

                    If (`$stopwatch.Elapsed.Seconds -lt `$scaledInterval) {
                        # Wait until the interval has been reached for the check.
                        Start-Sleep -Seconds `$timeToSleep | Out-Null
                        Write-PSLog @loggingDefaults -Method DEBUG -Message ""Sleeping Check Group :::  Sleep Time: `$(`$timeToSleep)s""
                    }
                    Else {
                        Write-Warning ""Job Took Longer Than Interval! Starting It Again Immediately""
                    }

                    [System.GC]::Collect()
                }# End while loop
            "

            # Add this command into the script block            
            $returnArray.($_.Group) += $jobCommand
        }
    }

    # Convert the value of each check group into a script block
    ForEach ($group in $returnArray.GetEnumerator().Name) {
        $returnArray.$group = [scriptblock]::Create($returnArray.$group)
    }

    Return $returnArray
}

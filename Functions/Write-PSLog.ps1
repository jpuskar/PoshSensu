Function Write-PSLog {
    [CmdletBinding()]
    Param (
        # The log message to write
        [Parameter(Mandatory=$true)]
        $Message,

        # The method to display the log message
        [Parameter(Mandatory=$false)]
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR")]
        [string]
        $Method,

        # The Path to write the log message
        [Parameter(Mandatory=$false)]
        [string]
        $Path = $null,

        # The maximum file size in MB of the log before it rolls over
        [Parameter(Mandatory=$false)]
        [string]
        $MaxFileSizeMB,

        # The Module or Function That Is Logging
        [Parameter(Mandatory=$true)]
        $ModuleName,

        # The level of logging to show. This is useful when you only want to log and show error logs for instance
        [Parameter(Mandatory=$false)]
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR")]
        $ShowLevel = 'DEBUG',

        [Parameter(Mandatory=$false)]
        [bool]$log_to_console = $false
    )

    Begin {
        # Create Log Directory
        If ($null -ne $path) {
            # Get the paths directory
            $pathDir = Split-Path -Path $Path -Parent

            If (-not(Test-Path -Path $pathDir)) {
                New-Item -Path $pathDir -ItemType Directory -Force | Out-Null
            }
        }

        [string]$date_str = Get-Date -Format s
        [string]$cur_process_str = [System.Diagnostics.Process]::GetCurrentProcess().Id

        $msg_hsh = @{}
        $msg_hsh.add("Datestamp", $date_str)
        $msg_hsh.add("CurrentProcess", $cur_process_str)
        $msg_hsh.add("ModuleName", [string]$ModuleName)
        $msg_hsh.add("Method", [string]$Method)
        $msg_hsh.add("Message", [string]$message)
        [string]$message = $msg_hsh | ConvertTo-Json -Compress
        # $Message = "$(Get-Date -Format s) [$([System.Diagnostics.Process]::GetCurrentProcess().Id)] - $($ModuleName) - $($Method) - $($Message)"

        Write-Verbose "Creating var write_ps_log_queue."
        $script:write_ps_log_queue = New-Object System.Collections.Queue
    }
    Process {
        # Set values for if the type of log will be actually shown
        If ($ShowLevel -ne $null) {
            Switch ($ShowLevel) {
                'DEBUG' { 
                    $showDebug = $true
                    $showInfo = $true
                    $showWarn = $true
                    $showError = $true
                 }
                'INFO' { 
                    $showDebug = $false
                    $showInfo = $true
                    $showWarn = $true
                    $showError = $true
                 }
                'WARN' { 
                    $showDebug = $false
                    $showInfo = $false
                    $showWarn = $true
                    $showError = $true
                 }
                'ERROR' { 
                    $showDebug = $false
                    $showInfo = $false
                    $showWarn = $false
                    $showError = $true
                 }
            }
        }

        Function Write-LogFile {
            [CmdletBinding()]
            Param (
                # The Path of the file to write
                [Parameter(Mandatory=$true)]
                $Path,
        
                # Maximum size of the log files
                [int]
                $MaxFileSizeMB,

                # The log message to write
                [Parameter(Mandatory=$true)]
                $Message
            )

            # Move the old log file over
            If (Test-Path -Path $Path) {
                $logFile = Get-Item -Path $Path

                # Convert log size to MB
                $logFileSizeInMB = ($logFile.Length / 1mb)

                If ($logFileSizeInMB -ge $MaxFileSizeMB) {
                    Move-Item -Path $Path -Destination ($Path + ".old") -Force
                }
            }

            Try {
                # TODO: Fail after queue reaches a certain size.
                While ($script:write_ps_log_queue.Count -gt 0) {
                    # Peak at the message and try and write it
                    $peek_results = $null
                    $peek_results = $script:write_ps_log_queue.Peek()
                    Add-Content -Path $Path -Value $peek_results -ErrorAction Stop

                    # If no failure, remove from queue
                    $script:write_ps_log_queue.Dequeue() | Out-Null
                    Write-Verbose ("Message de-queued and written to log file. " + $script:write_ps_log_queue.Count + " items remain in the queue.")
                }

                Add-Content -Path $Path -Value $message -ErrorAction Stop | Out-Null
            } Catch {
                # Add the message to the queue
                Write-Debug $_
                Write-Verbose "Log file busy, putting message in a queue."
                $script:write_ps_log_queue.Enqueue($message) | Out-Null
            }
        }
        
        If ($null -ne $Path) {
            $write_log_file_params = @{
                'Path' = $Path
                'MaxFileSizeMB' = $MaxFileSizeMB
                'Message' = $Message
            }
            Write-LogFile @write_log_file_params
        }

        If($log_to_console) {
            Switch ($Method) {
                'DEBUG' {
                    If ($showDebug) { Write-Verbose $Message }
                }
                'INFO' {
                    If ($showInfo) { Write-Output $Message }
                }
                'WARN' {
                    If ($showWarn) { Write-Warning $Message }
                }
                'ERROR' {
                    If ($showError) { Write-Error $Message }
                }
            }
        }
    }
    End{
        $script:write_ps_log_queue = $null
        [System.GC]::Collect()
    }
}
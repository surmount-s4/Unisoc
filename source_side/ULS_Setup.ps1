# ULS setup and bootstrap script.
# Installs Sysmon with fallback config, deploys ULS agent, and registers startup task.

[CmdletBinding()]
param(
    [ValidateSet("Install", "Verify", "Uninstall")]
    [string]$Mode = "Install",

    [string]$InstallRoot = "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [string]$TaskName = "ULS-Agent",

    [string]$SysmonExePath = "",
    [string]$PrimaryConfigPath = "",
    [string]$FallbackConfigPath = "",
    [string]$AgentScriptPath = "",

    [string]$RabbitMQHost = "",
    [int]$RabbitMQPort = 5672,
    [string]$RabbitMQUser = "",
    [string]$RabbitMQPassword = "",
    [string]$RabbitMQQueue = "security_events",
    [string]$RabbitMQVHost = "/",
    [int]$RabbitMQHttpPort = 15672,

    [int]$IntervalSeconds = 5,
    [int]$BatchSize = 100,
    [int]$InitialDaysBack = 0,

    [switch]$RemoveSysmonOnUninstall
)

$ErrorActionPreference = "Stop"
$script:SetupScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:LogFile = ""
$script:InputBoundParameters = @{} + $PSBoundParameters

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    if (-not [string]::IsNullOrWhiteSpace($script:LogFile)) {
        Add-Content -Path $script:LogFile -Value $line
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required. Run this script from an elevated PowerShell session."
    }
}

function Initialize-Logging {
    if (-not (Test-Path -Path $InstallRoot)) {
        New-Item -Path $InstallRoot -ItemType Directory -Force | Out-Null
    }

    $setupDir = Join-Path -Path $InstallRoot -ChildPath "setup"
    if (-not (Test-Path -Path $setupDir)) {
        New-Item -Path $setupDir -ItemType Directory -Force | Out-Null
    }

    $script:LogFile = Join-Path -Path $setupDir -ChildPath ("uls_setup_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    New-Item -Path $script:LogFile -ItemType File -Force | Out-Null
    Write-Log "Logging initialized at $script:LogFile"
}

function Resolve-SourcePaths {
    if ([string]::IsNullOrWhiteSpace($script:SysmonExePath)) {
        $script:SysmonExePath = Join-Path -Path $script:SetupScriptRoot -ChildPath "Sysmon.exe"
    }
    if ([string]::IsNullOrWhiteSpace($script:PrimaryConfigPath)) {
        $script:PrimaryConfigPath = Join-Path -Path $script:SetupScriptRoot -ChildPath "sysmon-config-comprehensive-updated.xml"
    }
    if ([string]::IsNullOrWhiteSpace($script:FallbackConfigPath)) {
        $script:FallbackConfigPath = Join-Path -Path $script:SetupScriptRoot -ChildPath "sysmon-config-comprehensive.xml"
    }
    if ([string]::IsNullOrWhiteSpace($script:AgentScriptPath)) {
        $script:AgentScriptPath = Join-Path -Path $script:SetupScriptRoot -ChildPath "ULS_Agent.ps1"
    }

    $required = @($script:SysmonExePath, $script:PrimaryConfigPath, $script:FallbackConfigPath, $script:AgentScriptPath)
    foreach ($path in $required) {
        if (-not (Test-Path -Path $path)) {
            throw "Required setup file not found: $path"
        }
    }

    Write-Log "Resolved setup sources successfully"
}

function Resolve-RabbitMQSettings {
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQHost") -and $env:RABBITMQ_HOST) {
        $script:RabbitMQHost = $env:RABBITMQ_HOST
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQPort") -and $env:RABBITMQ_PORT) {
        $parsedPort = 0
        if ([int]::TryParse($env:RABBITMQ_PORT, [ref]$parsedPort)) {
            $script:RabbitMQPort = $parsedPort
        }
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQUser") -and $env:RABBITMQ_USER) {
        $script:RabbitMQUser = $env:RABBITMQ_USER
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQPassword")) {
        if ($env:RABBITMQ_PASS) {
            $script:RabbitMQPassword = $env:RABBITMQ_PASS
        } elseif ($env:RABBITMQ_PASSWORD) {
            $script:RabbitMQPassword = $env:RABBITMQ_PASSWORD
        }
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQQueue") -and $env:RABBITMQ_QUEUE) {
        $script:RabbitMQQueue = $env:RABBITMQ_QUEUE
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQVHost") -and $env:RABBITMQ_VHOST) {
        $script:RabbitMQVHost = $env:RABBITMQ_VHOST
    }
    if (-not $script:InputBoundParameters.ContainsKey("RabbitMQHttpPort") -and $env:RABBITMQ_HTTP_PORT) {
        $parsedHttpPort = 0
        if ([int]::TryParse($env:RABBITMQ_HTTP_PORT, [ref]$parsedHttpPort)) {
            $script:RabbitMQHttpPort = $parsedHttpPort
        }
    }

    if ([string]::IsNullOrWhiteSpace($script:RabbitMQHost)) {
        $script:RabbitMQHost = "localhost"
    }
    if ([string]::IsNullOrWhiteSpace($script:RabbitMQUser)) {
        $script:RabbitMQUser = "admin"
    }
    if ([string]::IsNullOrWhiteSpace($script:RabbitMQPassword)) {
        throw "RabbitMQ password is required. Set -RabbitMQPassword or environment variable RABBITMQ_PASS/RABBITMQ_PASSWORD."
    }

    Write-Log "RabbitMQ target resolved host=$script:RabbitMQHost port=$script:RabbitMQPort queue=$script:RabbitMQQueue vhost=$script:RabbitMQVHost"
}

function Get-SysmonService {
    return Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Test-SysmonOperationalLog {
    try {
        $null = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    Write-Log ("Running: {0} {1}" -f $FilePath, ($Arguments -join " "))
    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        foreach ($line in $output) {
            Write-Log ("CMD: {0}" -f $line)
        }
    }

    Write-Log "Command exit code: $exitCode"
    return $exitCode
}

function Copy-SetupFiles {
    $targets = @(
        @{ Source = $SysmonExePath; Name = "Sysmon.exe" },
        @{ Source = $PrimaryConfigPath; Name = "sysmon-config-comprehensive-updated.xml" },
        @{ Source = $FallbackConfigPath; Name = "sysmon-config-comprehensive.xml" },
        @{ Source = $AgentScriptPath; Name = "ULS_Agent.ps1" }
    )

    foreach ($item in $targets) {
        $dest = Join-Path -Path $InstallRoot -ChildPath $item.Name
        Copy-Item -Path $item.Source -Destination $dest -Force
        Write-Log "Copied $($item.Name) to $dest"
    }
}

function Apply-SysmonConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    $installedSysmonExe = Join-Path -Path $InstallRoot -ChildPath "Sysmon.exe"
    $service = Get-SysmonService

    if ($null -eq $service) {
        $args = @("-accepteula", "-i", $ConfigPath)
        Write-Log "Sysmon not detected. Installing with config $ConfigPath"
    } else {
        $args = @("-c", $ConfigPath)
        Write-Log "Sysmon already installed ($($service.Name)). Updating config $ConfigPath"
    }

    $exitCode = Invoke-ExternalCommand -FilePath $installedSysmonExe -Arguments $args
    if ($exitCode -ne 0) {
        Write-Log "Sysmon command failed for config $ConfigPath" "WARN"
        return $false
    }

    $service = Get-SysmonService
    if ($null -eq $service) {
        Write-Log "Sysmon service was not found after applying config." "WARN"
        return $false
    }

    if ($service.Status -ne "Running") {
        Start-Service -Name $service.Name
        Write-Log "Started Sysmon service: $($service.Name)"
    }

    if (-not (Test-SysmonOperationalLog)) {
        Write-Log "Sysmon Operational log channel is not available." "WARN"
        return $false
    }

    Write-Log "Sysmon config applied successfully: $ConfigPath"
    return $true
}

function Register-OrUpdateAgentTask {
    $installedAgentPath = Join-Path -Path $InstallRoot -ChildPath "ULS_Agent.ps1"
    $agentFallback = Join-Path -Path $InstallRoot -ChildPath "fallback_events.json"

    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy Bypass",
        ("-File `"{0}`"" -f $installedAgentPath),
        ("-RabbitMQHost `"{0}`"" -f $RabbitMQHost),
        ("-RabbitMQPort {0}" -f $RabbitMQPort),
        ("-RabbitMQUser `"{0}`"" -f $RabbitMQUser),
        ("-RabbitMQPassword `"{0}`"" -f $RabbitMQPassword),
        ("-RabbitMQQueue `"{0}`"" -f $RabbitMQQueue),
        ("-RabbitMQVHost `"{0}`"" -f $RabbitMQVHost),
        ("-RabbitMQHttpPort {0}" -f $RabbitMQHttpPort),
        ("-IntervalSeconds {0}" -f $IntervalSeconds),
        ("-BatchSize {0}" -f $BatchSize),
        ("-InitialDaysBack {0}" -f $InitialDaysBack),
        ("-FallbackPath `"{0}`"" -f $agentFallback)
    )
    $argString = $argList -join " "

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argString
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Removed existing scheduled task $TaskName"
    }

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "ULS agent event forwarder"
    Start-ScheduledTask -TaskName $TaskName
    Write-Log "Scheduled task registered and started: $TaskName"
}

function Install-ULS {
    Assert-Administrator
    Initialize-Logging
    Resolve-SourcePaths
    Resolve-RabbitMQSettings

    Copy-SetupFiles

    $primaryInstalledPath = Join-Path -Path $InstallRoot -ChildPath "sysmon-config-comprehensive-updated.xml"
    $fallbackInstalledPath = Join-Path -Path $InstallRoot -ChildPath "sysmon-config-comprehensive.xml"

    $primaryOk = Apply-SysmonConfig -ConfigPath $primaryInstalledPath
    if (-not $primaryOk) {
        Write-Log "Primary Sysmon config failed, trying fallback config" "WARN"
        $fallbackOk = Apply-SysmonConfig -ConfigPath $fallbackInstalledPath
        if (-not $fallbackOk) {
            throw "Both Sysmon configs failed. Check setup log: $script:LogFile"
        }
    }

    Register-OrUpdateAgentTask

    Write-Log "Install completed successfully"
}

function Verify-ULS {
    Assert-Administrator
    Initialize-Logging

    $checks = @(
        Join-Path -Path $InstallRoot -ChildPath "Sysmon.exe",
        Join-Path -Path $InstallRoot -ChildPath "sysmon-config-comprehensive-updated.xml",
        Join-Path -Path $InstallRoot -ChildPath "sysmon-config-comprehensive.xml",
        Join-Path -Path $InstallRoot -ChildPath "ULS_Agent.ps1"
    )

    foreach ($path in $checks) {
        if (-not (Test-Path -Path $path)) {
            throw "Missing expected file: $path"
        }
        Write-Log "Verified file exists: $path"
    }

    $service = Get-SysmonService
    if ($null -eq $service) {
        throw "Sysmon service is not installed."
    }
    if ($service.Status -ne "Running") {
        throw "Sysmon service is installed but not running."
    }
    Write-Log "Sysmon service running: $($service.Name)"

    if (-not (Test-SysmonOperationalLog)) {
        throw "Sysmon Operational log is not available."
    }
    Write-Log "Sysmon Operational log is available"

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        throw "Scheduled task not found: $TaskName"
    }
    Write-Log "Scheduled task present: $TaskName"

    Write-Log "Verify completed successfully"
}

function Uninstall-ULS {
    Assert-Administrator
    Initialize-Logging

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Removed scheduled task: $TaskName"
    } else {
        Write-Log "Scheduled task not found: $TaskName"
    }

    if ($RemoveSysmonOnUninstall) {
        $installedSysmonExe = Join-Path -Path $InstallRoot -ChildPath "Sysmon.exe"
        if (Test-Path -Path $installedSysmonExe) {
            $exitCode = Invoke-ExternalCommand -FilePath $installedSysmonExe -Arguments @("-u", "force")
            if ($exitCode -eq 0) {
                Write-Log "Sysmon removed"
            } else {
                Write-Log "Sysmon uninstall command failed" "WARN"
            }
        } else {
            Write-Log "Sysmon executable not found under install root, skip uninstall"
        }
    }

    Write-Log "Uninstall completed"
}

try {
    switch ($Mode) {
        "Install" { Install-ULS }
        "Verify" { Verify-ULS }
        "Uninstall" { Uninstall-ULS }
    }
    exit 0
} catch {
    if (-not [string]::IsNullOrWhiteSpace($script:LogFile)) {
        Write-Log $_.Exception.Message "ERROR"
    } else {
        Write-Error $_.Exception.Message
    }
    exit 1
}

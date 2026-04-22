param(
    [string]$DbHost = "localhost",
    [int]$DbPort = 5432,
    [string]$AdminDatabase = "postgres",
    [string]$AdminUser = "postgres",
    [string]$AdminPassword = "postgres",
    [string]$AppDatabase = "uls_detection",
    [string]$AppUser = "uls_user",
    [string]$AppPassword = "ChangeThisPassword123!",
    [string]$SchemaFile = "",
    [string]$DockerContainer = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[setup-postgres] $Message"
}

function Escape-SqlLiteral {
    param([string]$Value)
    return $Value.Replace("'", "''")
}

function Assert-SimpleIdentifier {
    param(
        [string]$Value,
        [string]$Name
    )

    if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        throw "$Name must match ^[A-Za-z_][A-Za-z0-9_]*$ for this script. Value: $Value"
    }
}

function Invoke-PsqlQuery {
    param(
        [string]$Database,
        [string]$Sql,
        [switch]$TuplesOnly
    )

    if (-not [string]::IsNullOrWhiteSpace($DockerContainer)) {
        $args = @(
            "exec", "-i",
            "-e", "PGPASSWORD=$AdminPassword",
            $DockerContainer,
            "psql",
            "-v", "ON_ERROR_STOP=1",
            "-U", $AdminUser,
            "-d", $Database
        )

        if ($TuplesOnly) {
            $args += @("-t", "-A")
        }

        $args += @("-c", $Sql)
        $result = & docker @args 2>&1
    }
    else {
        $args = @(
            "-v", "ON_ERROR_STOP=1",
            "-h", $DbHost,
            "-p", "$DbPort",
            "-U", $AdminUser,
            "-d", $Database
        )

        if ($TuplesOnly) {
            $args += @("-t", "-A")
        }

        $args += @("-c", $Sql)
        $result = & psql @args 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw "psql command failed: $($result | Out-String)"
    }

    return ($result | Out-String)
}

function Invoke-PsqlFile {
    param(
        [string]$Database,
        [string]$FilePath
    )

    if (-not (Test-Path -Path $FilePath)) {
        throw "Schema file not found: $FilePath"
    }

    if (-not [string]::IsNullOrWhiteSpace($DockerContainer)) {
        $sql = Get-Content -Path $FilePath -Raw
        $result = $sql | & docker exec -i -e "PGPASSWORD=$AdminPassword" $DockerContainer psql -v ON_ERROR_STOP=1 -U $AdminUser -d $Database 2>&1
    }
    else {
        $args = @(
            "-v", "ON_ERROR_STOP=1",
            "-h", $DbHost,
            "-p", "$DbPort",
            "-U", $AdminUser,
            "-d", $Database,
            "-f", $FilePath
        )
        $result = & psql @args 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Schema apply failed: $($result | Out-String)"
    }

    return ($result | Out-String)
}

try {
    Assert-SimpleIdentifier -Value $AppDatabase -Name "AppDatabase"
    Assert-SimpleIdentifier -Value $AppUser -Name "AppUser"

    if ([string]::IsNullOrWhiteSpace($SchemaFile)) {
        $scriptRoot = Split-Path -Parent $PSCommandPath
        $SchemaFile = Join-Path $scriptRoot "02-init-uls-schema.sql"
    }

    if ([string]::IsNullOrWhiteSpace($DockerContainer)) {
        if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
            throw "psql was not found in PATH. Install PostgreSQL client tools or pass -DockerContainer."
        }
        $env:PGPASSWORD = $AdminPassword
    }
    else {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            throw "docker was not found in PATH, but -DockerContainer was provided."
        }
        Write-Step "Using docker container mode: $DockerContainer"
    }

    $appDbLiteral = Escape-SqlLiteral -Value $AppDatabase
    $appUserLiteral = Escape-SqlLiteral -Value $AppUser
    $appPassLiteral = Escape-SqlLiteral -Value $AppPassword

    Write-Step "Ensuring application role exists: $AppUser"
    $roleSql = @"
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$appUserLiteral') THEN
        ALTER ROLE "$AppUser" WITH LOGIN PASSWORD '$appPassLiteral';
    ELSE
        CREATE ROLE "$AppUser" WITH LOGIN PASSWORD '$appPassLiteral';
    END IF;
END
$$;
"@
    [void](Invoke-PsqlQuery -Database $AdminDatabase -Sql $roleSql)

    Write-Step "Ensuring database exists: $AppDatabase"
    $existsSql = "SELECT 1 FROM pg_database WHERE datname = '$appDbLiteral';"
    $dbExists = (Invoke-PsqlQuery -Database $AdminDatabase -Sql $existsSql -TuplesOnly).Trim()

    if ([string]::IsNullOrWhiteSpace($dbExists)) {
        $createDbSql = "CREATE DATABASE `"$AppDatabase`" OWNER `"$AppUser`";"
        [void](Invoke-PsqlQuery -Database $AdminDatabase -Sql $createDbSql)
        Write-Step "Created database $AppDatabase"
    }
    else {
        Write-Step "Database already exists: $AppDatabase"
    }

    Write-Step "Granting database privileges"
    $grantDbSql = "GRANT ALL PRIVILEGES ON DATABASE `"$AppDatabase`" TO `"$AppUser`";"
    [void](Invoke-PsqlQuery -Database $AdminDatabase -Sql $grantDbSql)

    Write-Step "Applying schema file: $SchemaFile"
    [void](Invoke-PsqlFile -Database $AppDatabase -FilePath $SchemaFile)

    Write-Step "Granting schema/table/sequence privileges"
    $grantsSql = @"
GRANT USAGE, CREATE ON SCHEMA public TO "$AppUser";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "$AppUser";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "$AppUser";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "$AppUser";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "$AppUser";
"@
    [void](Invoke-PsqlQuery -Database $AppDatabase -Sql $grantsSql)

    Write-Step "Verifying expected tables"
    $verifySql = @"
SELECT tablename
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN (
    'security_events',
    'firewall_events',
    'scada_logs',
    'llm_pass_1',
    'correlation_incidents',
    'correlation_windows',
    'bart_event_decisions',
    'process_chain'
  )
ORDER BY tablename;
"@
    $tables = Invoke-PsqlQuery -Database $AppDatabase -Sql $verifySql -TuplesOnly
    Write-Host $tables

    Write-Step "Setup completed successfully"
    Write-Host ""
    Write-Host "Use these environment values in your server configuration:"
    Write-Host "POSTGRES_HOST=$DbHost"
    Write-Host "POSTGRES_PORT=$DbPort"
    Write-Host "POSTGRES_USER=$AppUser"
    Write-Host "POSTGRES_PASS=$AppPassword"
    Write-Host "POSTGRES_DB=$AppDatabase"
}
finally {
    if ($env:PGPASSWORD) {
        Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    }
}

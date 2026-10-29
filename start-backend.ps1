<#
.SYNOPSIS
    Starts the AUTO-RECON AI Spring Boot backend.
.DESCRIPTION
    Checks prerequisites (Java, Maven wrapper, database configuration),
    verifies database connectivity, and launches the Spring Boot application.
#>

[CmdletBinding()]
param(
    [switch]$SkipDbCheck,
    [string]$Port
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       AUTO-RECON AI - Spring Boot Backend Launcher      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Java Availability
Write-Host "`n[1/4] Checking Java runtime environment..." -ForegroundColor Yellow
$javaCmd = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaCmd) {
    Write-Host "`n[ERROR] Java was not detected on your PATH." -ForegroundColor Red
    Write-Host "Please ensure Java 21+ (or a compatible JDK) is installed and available in your environment." -ForegroundColor Red
    exit 1
}

$origEA = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$javaVerOutput = & java -version 2>&1
$ErrorActionPreference = $origEA
$verLine = ($javaVerOutput | Select-Object -First 1)
Write-Host "      Found: $verLine ($($javaCmd.Source))" -ForegroundColor Green

# 2. Locate Backend Directory and Maven Wrapper
$backendDir = Join-Path $PSScriptRoot "spring-backend"
if (-not (Test-Path $backendDir)) {
    Write-Host "`n[ERROR] Backend directory '$backendDir' does not exist." -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/4] Checking build tools and Maven wrapper..." -ForegroundColor Yellow
$mvnCmd = Join-Path $backendDir "mvnw.cmd"
if (Test-Path $mvnCmd) {
    Write-Host "      Using Maven Wrapper: $mvnCmd" -ForegroundColor Green
    $runCmd = $mvnCmd
} else {
    try {
        $mvnVer = & mvn -v 2>&1
        Write-Host "      Using system Maven: $($mvnVer | Select-Object -First 1)" -ForegroundColor Green
        $runCmd = "mvn"
    } catch {
        Write-Host "`n[ERROR] Neither the Maven wrapper ($mvnCmd) nor system 'mvn' was found." -ForegroundColor Red
        exit 1
    }
}

# 3. Load Environment Variables & Check Database Configuration
Write-Host "`n[3/4] Resolving MySQL database configuration..." -ForegroundColor Yellow

# Check for .env file in spring-backend or root
$envFile = $null
if (Test-Path (Join-Path $backendDir ".env")) {
    $envFile = Join-Path $backendDir ".env"
} elseif (Test-Path (Join-Path $PSScriptRoot ".env")) {
    $envFile = Join-Path $PSScriptRoot ".env"
}

if ($envFile) {
    Write-Host "      Loading environment variables from: $envFile" -ForegroundColor Cyan
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not ($line.StartsWith("#")) -and ($line.Contains("="))) {
            $parts = $line.Split("=", 2)
            $name = $parts[0].Trim()
            $val = $parts[1].Trim()
            if (-not [string]::IsNullOrEmpty($name)) {
                [System.Environment]::SetEnvironmentVariable($name, $val, [System.EnvironmentVariableTarget]::Process)
            }
        }
    }
} else {
    Write-Host "      No .env file found. Using default or system environment variables." -ForegroundColor Gray
}

# Resolve variables with safe defaults
$dbHost = if ($env:DB_HOST) { $env:DB_HOST } else { "127.0.0.1" }
$dbPort = if ($env:DB_PORT) { [int]$env:DB_PORT } else { 3306 }
$dbName = if ($env:DB_NAME) { $env:DB_NAME } else { "auto_recon" }
$dbUser = if ($env:DB_USER) { $env:DB_USER } else { "autorecon_app" }
$serverPort = if ($Port) { $Port } elseif ($env:SERVER_PORT) { $env:SERVER_PORT } else { "8080" }

$env:DB_HOST = $dbHost
$env:DB_PORT = "$dbPort"
$env:DB_NAME = $dbName
$env:DB_USER = $dbUser
$env:SERVER_PORT = $serverPort

Write-Host "      Target Host     : $dbHost" -ForegroundColor Gray
Write-Host "      Target Port     : $dbPort" -ForegroundColor Gray
Write-Host "      Database Name   : $dbName" -ForegroundColor Gray
Write-Host "      Database User   : $dbUser" -ForegroundColor Gray
Write-Host "      HTTP Port       : $serverPort" -ForegroundColor Gray

# Optional Database Port Pre-Flight Check
if (-not $SkipDbCheck) {
    Write-Host "      Verifying network reachability of MySQL at $($dbHost):$($dbPort)..." -ForegroundColor Gray
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $iar = $tcpClient.BeginConnect($dbHost, $dbPort, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(2000, $false)
        if (-not $wait) {
            $tcpClient.Close()
            throw "Connection timed out after 2000ms"
        }
        $tcpClient.EndConnect($iar)
        $tcpClient.Close()
        Write-Host "      MySQL port is listening and reachable." -ForegroundColor Green
    } catch {
        Write-Host "`n[WARNING] Could not open a TCP connection to MySQL at $($dbHost):$($dbPort)." -ForegroundColor Yellow
        Write-Host "          Ensure your MySQL service is running and database '$dbName' is created." -ForegroundColor Yellow
        Write-Host "          Run setup script: Get-Content database/setup.sql | mysql -u root -p" -ForegroundColor Yellow
        Write-Host "          Continuing startup (Spring Boot will display detailed connection logs)...`n" -ForegroundColor Gray
    }
}

# 4. Launch Spring Boot
Write-Host "`n[4/4] Starting Spring Boot application on port $serverPort..." -ForegroundColor Yellow
Write-Host "      API Base URL    : http://localhost:$serverPort/api" -ForegroundColor Cyan
Write-Host "      Health Check    : http://localhost:$serverPort/api/health" -ForegroundColor Cyan
Write-Host "      Evidence Ledger : http://localhost:$serverPort/api/evidence" -ForegroundColor Cyan
Write-Host "`nPress Ctrl+C to stop the backend process.`n" -ForegroundColor DarkGray

Push-Location $backendDir
try {
    if ($runCmd -eq "mvn") {
        & mvn spring-boot:run
    } else {
        & $runCmd spring-boot:run
    }
} finally {
    Pop-Location
}

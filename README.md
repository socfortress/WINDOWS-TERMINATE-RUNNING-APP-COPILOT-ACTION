Paste your rich text content here. You can paste directly from Word or other rich text sources.

\# PowerShell Active Response Template – Terminate App Script

  

This repository serves as a template for creating PowerShell-based active response scripts for security automation and incident response. The template provides a standardized structure and common functions to ensure consistent logging, error handling, and execution flow across all active response scripts.

  

\## Overview

  

The \`Terminate-App.ps1\` file is based on the template and provides a mechanism to \*\*terminate a running process by name or PID\*\*. It logs all actions, handles errors gracefully, outputs JSON results for SIEM/SOAR integration, and maintains log rotation to prevent log growth issues.

  

\## Template Structure

  

\### Core Components

  

The script includes the following essential components:

  

1. \*\*Parameter Definitions\*\* – Configurable log paths for script and active response logs

2. \*\*Logging Framework\*\* – Built-in logging with rotation

3. \*\*Error Handling\*\* – Structured exception management

4. \*\*JSON Output\*\* – Standardized response format for SIEM/SOAR ingestion

5. \*\*Execution Timing\*\* – Tracks script execution duration

  

\## How Scripts Are Invoked

  

\### Command Line Execution

\`\`\`powershell

.\\Terminate-App.ps1 \[-LogPath <string\>\] \[-ARLog <string\>\]

  

Parameters

Parameter Type Default Value Description

LogPath string $env:TEMP\\TerminateApp-script.log Path for detailed execution logs

ARLog string C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log Path for active response JSON output

Example Invocations

  

\# Basic execution with defaults (prompts for process name or PID interactively)

.\\Terminate-App.ps1

  

\# Specify a custom log path

.\\Terminate-App.ps1 -LogPath "C:\\Logs\\TerminateApp.log"

  

\# Integration with OSSEC/Wazuh active response

.\\Terminate-App.ps1 -ARLog "C:\\ossec\\active-responses.log"

  

Template Functions

Write-Log

  

Purpose: Provides standardized logging with multiple severity levels and console output.

  

Parameters:

  

Message (string): The log message to write

  

Level (ValidateSet): Log level – 'INFO', 'WARN', 'ERROR', 'DEBUG'

  

Features:

  

Timestamp formatting with milliseconds

  

Color-coded console output based on severity

  

File logging with structured format

  

Verbose debugging support

  

Usage:

  

Write-Log "Terminated process PID 1234 \[notepad\]" 'INFO'

Write-Log "No process found with PID 1234" 'WARN'

Write-Log "Critical error occurred" 'ERROR'

  

Rotate-Log

  

Purpose: Manages log file size and implements automatic log rotation.

  

Features:

  

Monitors log file size (100KB threshold by default)

  

Keeps 5 historical logs ($LogKeep = 5)

  

Rotates when size exceeded to preserve forensic logs

  

Configuration Variables:

  

$LogMaxKB = 100

  

$LogKeep = 5

  

Script Execution Flow

1\. Initialization Phase

  

Validates and sets default parameters

  

Configures error preferences

  

Collects hostname and environment variables

  

Rotates logs if exceeding 100KB

  

2\. Execution Phase

  

Prompts for target process (name or PID)

  

Terminates matching process(es) using Stop-Process

  

Logs all terminations with timestamps

  

Handles cases when no process is found

  

3. Completion Phase

  

Appends JSON result to $ARLog

  

Includes fields: timestamp, host, action, mode, target, status, killed

  

Logs script duration

  

4. Error Handling

  

Catches all exceptions

  

Logs error messages and outputs standardized JSON error responses

  

Ensures graceful exit

  

JSON Output Format

  

All scripts output standardized JSON responses to the active response log:

Success Response

  

{

"timestamp": "2025-07-19T10:30:45.123Z",

"host": "HOSTNAME",

"action": "terminate\_app",

"mode": "pid",

"target": "1234",

"status": "terminated",

"killed": \[

{"name": "notepad", "pid": 1234}

\]

}

  

Not Found Response

  

{

"timestamp": "2025-07-19T10:30:45.123Z",

"host": "HOSTNAME",

"action": "terminate\_app",

"mode": "name",

"target": "badprocess",

"status": "not\_found",

"killed": \[\]

}

  

Error Response

  

{

"timestamp": "2025-07-19T10:30:45.123Z",

"host": "HOSTNAME",

"action": "terminate\_app",

"status": "error",

"error": "Access denied"

}

  

Implementation Guidelines

  

Copy Terminate-App.ps1 as needed for similar response scripts

  

Update only the action logic (process termination logic in this case)

  

Maintain JSON field consistency (action: terminate\_app)

  

Validate user input (PID or process name)

  

Security Considerations

  

Run with minimal privileges — only as elevated if killing protected processes

  

Validate input (avoid injection or improper targets)

  

Ensure $ARLog and $LogPath have correct permissions

  

All terminations are logged for auditing

  

Troubleshooting

  

Permission Errors: Run with admin privileges if terminating protected processes

  

No Matches: Ensure the name or PID is correct

  

Timeout: Not applicable (interactive script, no long-running ops)

  

Log Rotation: Check $LogPath directory write permissions

  

Contributing

  

When creating new active response scripts based on this template:

  

Maintain the core logging and error handling structure

  

Follow PowerShell best practices and coding standards

  

Document any additional functions or parameters

  

Test thoroughly in isolated environments

  

Include usage examples and expected outputs

  

Automated Releases

  

This repository includes automated release functionality via GitHub Actions that creates production-ready PowerShell scripts for distribution.

Release Features

  

Automated Script Packaging: Adds metadata headers with version, build date, and repository information

  

Multiple Distribution Formats: Creates both versioned and generic script names

  

Integrity Verification: Generates SHA256 checksums for all release files

  

Automated Installer: Provides a PowerShell installer script for easy deployment

  

Production Documentation: Includes comprehensive usage and security documentation

  

Creating Releases

Method 1: Git Tags (Recommended)

  

\# Create and push a version tag

git tag v1.0.0

git push origin v1.0.0

  

Method 2: Manual Workflow Trigger

  

Go to the Actions tab in GitHub

  

Select "Create PowerShell Script Release"

  

Click "Run workflow"

  

Enter the version (e.g., v1.0.0) and script name

  

Click "Run workflow"

  

Release Artifacts

  

Each release contains:

  

Terminate-App.ps1 – Production script with metadata

  

Terminate-App-v1.0.0.ps1 – Versioned production script

  

install.ps1 – Automated installation script

  

checksums.txt – SHA256 file integrity checksums

  

README.md – Release-specific documentation

  

Distribution Methods

Option 1: Automated Installation

  

\# Download and run the installer

Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/install.ps1" -OutFile "install.ps1"

.\\install.ps1

  

Option 2: Direct Download

  

\# Download script directly

Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/Terminate-App.ps1" -OutFile "Terminate-App.ps1"

  

Option 3: One-liner Execution

  

\# Execute directly from URL (use with caution)

Invoke-WebRequest -Uri "https://github.com/{owner}/{repo}/releases/download/v1.0.0/Terminate-App.ps1" | Invoke-Expression

  

Production Deployment

  

For production environments, the recommended approach is:

  

Use the automated installer for validated deployments

  

Verify checksums to ensure script integrity

  

Test in isolated environments before production deployment

  

Use proper execution policies and security controls

  

Monitor script execution through the built-in logging framework

  

Why Not Compiled Scripts?

  

For PowerShell active response scripts, raw .ps1 files with metadata headers provide the best balance of:

  

Transparency: Source code is visible and auditable

  

Flexibility: Easy to modify for specific environments

  

Compatibility: Works across different PowerShell versions and platforms

  

Security: Can be signed and verified without complex packaging

  

Debugging: Easier to troubleshoot and customize when needed

  

However, for environments requiring additional security or deployment simplification, consider:

  

Code signing with digital certificates

  

Module packaging for reusable components

  

PowerShell galleries for internal distribution

  

Group Policy deployment for enterprise environments

  

License

  

This template is provided as-is for security automation and incident response purposes.

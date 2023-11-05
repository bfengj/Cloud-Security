# AWS Configuration
$accessKey = "AKIA3SFMDAPOWOWKXEHU"
$secretKey = "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"
$region = "us-east-1"

# Set up AWS hardcoded credentials
Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey

# Set the AWS region
Set-DefaultAWSRegion -Region $region

# Read the secrets from export.xml
[xml]$xmlContent = Get-Content -Path "export.xml"

# Output log file
$logFile = "upload_log.txt"

# Error handling with retry logic
function TryUploadSecret($secretName, $secretValue) {
    $retries = 3
    while ($retries -gt 0) {
        try {
            $result = New-SECSecret -Name $secretName -SecretString $secretValue
            $logEntry = "Successfully uploaded secret: $secretName with ARN: $($result.ARN)"
            Write-Output $logEntry
            Add-Content -Path $logFile -Value $logEntry
            return $true
        } catch {
            $retries--
            Write-Error "Failed attempt to upload secret: $secretName. Retries left: $retries. Error: $_"
        }
    }
    return $false
}

foreach ($secretNode in $xmlContent.Secrets.Secret) {
    # Implementing concurrency using jobs
    Start-Job -ScriptBlock {
        param($secretName, $secretValue)
        TryUploadSecret -secretName $secretName -secretValue $secretValue
    } -ArgumentList $secretNode.Name, $secretNode.Value
}

# Wait for all jobs to finish
$jobs = Get-Job
$jobs | Wait-Job

# Retrieve and display job results
$jobs | ForEach-Object {
    $result = Receive-Job -Job $_
    if (-not $result) {
        Write-Error "Failed to upload secret: $($_.Name) after multiple retries."
    }
    # Clean up the job
    Remove-Job -Job $_
}

Write-Output "Batch upload complete!"


# Install-Module -Name AWSPowerShell -Scope CurrentUser -Force
# .\migrate_secrets.ps1
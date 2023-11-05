# Install the required modules if not already installed
Install-Module -Name Az -Force -Scope CurrentUser
Install-Module -Name MSAL.PS -Force -Scope CurrentUser

# Import the required modules
Import-Module Az
Import-Module MSAL.PS

# Define your Azure AD credentials
$Username = "marcus@megabigtech.com"
$Password = "TheEagles12345!" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

# Authenticate to Azure AD using the specified credentials
Connect-AzureAD -Credential $Credential

# Define the Microsoft Graph API URL
$GraphApiUrl = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName"

# Retrieve the access token for Microsoft Graph
$AccessToken = (Get-AzAccessToken -ResourceType MSGraph).Token

# Create a headers hashtable with the access token
$headers = @{
    "Authorization" = "Bearer $AccessToken"
    "ContentType"   = "application/json"
}

# Retrieve User Information and Last Sign-In Time using Microsoft Graph via PowerShell
$response = Invoke-RestMethod -Uri $GraphApiUrl -Method Get -Headers $headers

# Output the response (formatted as JSON)
$response | ConvertTo-Json

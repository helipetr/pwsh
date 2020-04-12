using namespace Microsoft.IdentityModel.Clients.ActiveDirectory

<#
	Script that pulls all Exchange Online legacy auth sign-in events from Azure AD sign-in logs from the last 30 days. 
	
	Implementation is heavily inspired by 
		GitHub project PullAzureADSignInReports / https://github.com/TspringMSFT/PullAzureADSignInReports-
		and a blog by Stephan Wälde / https://stephanwaelde.com/2019/12/26/user-sign-ins/

	Author: Pete Helin, @helipetr / 12.4.2020
	
	Syntax:
	.\Get-EXOLegacySignins.ps1
#>

$DebugPreference = "Continue"
$ErrorActionPreference = "Stop"

# Binding AAD dlls, AzureADPreview works as well
$AADModule = Get-Module -Name "AzureAD" -ListAvailable
[System.Reflection.Assembly]::LoadFrom($(Join-Path $AADModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll")) | out-null
[System.Reflection.Assembly]::LoadFrom($(Join-Path $AADModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll")) | out-null

# Global multi-tenant Azure AD PowerShell ClientID 1b730954-1685-4b74-9bfd-dac224a7b894
# Includes delegated permissions for 
#  AuditLog.Read.All
#  Directory.AccessAsUser.All
#  Directory.ReadWrite.All
#  Group.ReadWrite.All
$ClientID  = "1b730954-1685-4b74-9bfd-dac224a7b894" 

#Parameters for Graph API
$resourceURI = "https://graph.microsoft.com"
$authority = "https://login.microsoftonline.com/common"

# clientApps we are interested in, 
# e.g. Exchange Online basic auth client apps
$legacyClients = @(
"Other clients",
"Exchange Web Services",
"MAPI Over HTTP",
"POP3",
"Outlook Anywhere (RPC over HTTP)",
"IMAP4",
"AutoDiscover",
"Offline Address Book",
"Authenticated SMTP",
"Exchange Online PowerShell",
"Exchange ActiveSync"
)

# Graph API (delegated permissions)

# Credentials for reading sign-in logs
# to read AAD signin logs admin permissions are required, eg. Security Reader or Global Reader role
$userid = read-host "Enter user name (upn)" 
$securepwd = read-host "Enter pa$$w0rd! for $userid" -AsSecureString

$uc = new-object UserPasswordCredential -ArgumentList $userid, $securepwd

# Graph API authentication
$authContext = New-Object AuthenticationContext -ArgumentList $authority
$authResponse = [AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceURI, $ClientID, $uc)
$authResult = $authResponse.result 

Write-Debug "Auth status: $($authResponse.Status)"
Write-Debug "Auth access token type: $($authResult.AccessTokenType)"

if ($($authResponse.Exception)) {

	Write-Output "Authentication failed!"
	Write-Debug "Auth exception: $($authResponse.Exception)"
	Exit
}

<#
	DEBUG: Auth status: RanToCompletion
	DEBUG: Auth access token type: Bearer
#>

<#
	DEBUG: Auth status: Faulted
	DEBUG: Auth exception: System.AggregateException: One or more errors occurred. --->
	Microsoft.IdentityModel.Clients.ActiveDirectory.AdalClaimChallengeException: AADSTS50076: Due to a configuration change
	 made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access
	 '00000003-0000-0000-c000-000000000000'.
#>

# build header for REST request
$headers = @{}
$headers.Add('Authorization','Bearer ' + $authResult.AccessToken)
$headers.Add('Content-Type', "application/json")

# start parsing dates for the report
# fetching all legacy sign-ins during the last 30 days 

# basically getting all available, since logs are retained only for 30 days
$reportingStartDate = (Get-Date).ToUniversalTime().Date.AddDays(-30)
$reportingEndDate = (Get-Date).ToUniversalTime().Date

# how many minutes to get at one go, reduce this if querying against large & busy tenants
$timespanMinutes = 480 # 8h

# set initial "nextstarttime" for web request
$nextstarttime = $reportingStartDate

Do {

	# get log entries for a specified time span
	$fromtime = $nextstarttime # set "from" as the ending datetime from the previous time window
	$totime = $fromtime.AddMinutes($timespanMinutes)
	
	# ensure totime is in spesified timeframe, if passes it, set end date as report end datetime
	if ($totime -gt $reportingEndDate) { $totime = $reportingEndDate }

	# NOTE: filtering is very sensitive to datetime format, date must be like: 2020-02-05T14:01:02Z
	# convert to "sortable" format
	$from = $($fromtime.ToString("s")) + "Z"
	$to = $($totime.ToString("s")) + "Z"

	Write-Debug "Request from $from"
	Write-Debug "Request to $to"

	#set start for the next round in do-while
	$nextstarttime = $totime

	# generate only one log file for each day, append results to AAD_LegacySignInReport_yyyyMMdd.csv
	$now = "{0:yyyyMMdd}" -f $fromtime
	$outputFile = ".\AAD_LegacySignInReport_$now.csv"

	# generate request URLs for each legacy client type, using given time range
	$urls = @()
	$legacyClients|%{
		$urls += "https://graph.microsoft.com/beta/auditLogs/signIns?"+`
		"`$filter="+`
		"createdDateTime%20ge%20" + $from + "%20"+`
		"and%20createdDateTime%20le%20" + $to + "%20"+`
		"and%20clientAppUsed%20eq%20'" + $_ +`
		"'&`$top=1000"
	}
	#$url =$urls|select -f 1
	foreach ($url in $urls) {

		# reset counters and flags for new urls
		$count=0
		$retryCount = 0
		$oneSuccessfulFetch = $False

		# start the request
		Do {
			Write-Output "Requesting sign-ins: $url"

			Try {
				
				# get data and convert json payload
				$myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $url)
				$results = ($myReport.Content | ConvertFrom-Json).value
				
				# reset retry flags
				$oneSuccessfulFetch = $true
				$retryCount = 0
				
				# export sign-in data to CSV
				
				$results | `
					select `
					createdDateTime,
					userDisplayName,userPrincipalName,userId,`
					appId,appDisplayName,`
					ipAddress,`
					clientAppUsed,`
					userAgent,`
					conditionalAccessStatus,`
					isInteractive,`
					resourceDisplayName,resourceId,`
					mfaDetail,`
					@{Name='status.errorCode'; Expression={$_.status.errorCode}},`
					@{Name='status.failureReason'; Expression={$_.status.failureReason}},`
					@{Name='status.additionalDetails'; Expression={$_.status.additionalDetails}},`
					@{Name='location.countryOrRegion'; Expression={$_.location.countryOrRegion}},`
					@{Name='location.city'; Expression={$_.location.city}},`
					@{Name='device.deviceId'; Expression={$_.deviceDetail.deviceId}},`
					@{Name='device.displayName'; Expression={$_.DeviceDetail.displayName}},`
					@{Name='device.operatingSystem'; Expression={$_.DeviceDetail.operatingSystem}},`
					@{Name='device.browser'; Expression={$_.DeviceDetail.browser}},`
					@{Name='device.isCompliant'; Expression={$_.DeviceDetail.isCompliant}},`
					@{Name='device.isManaged'; Expression={$_.DeviceDetail.isManaged}},`
					@{Name='device.trustType'; Expression={$_.DeviceDetail.trustType}}`
					| Export-Csv $outputFile -Append -NoTypeInformation -Encoding UTF8
				
				# if request returns over 1000 events, next query url is returned
				$url = ($myReport.Content | ConvertFrom-Json).'@odata.nextLink'
				
				$count = $count+$results.Count
				Write-Output "$count events returned"
				
			}
			Catch [System.Net.WebException] {
				
				$statusCode = [int]$_.Exception.Response.StatusCode
				
				Write-Output $statusCode
				Write-Output $_.Exception.Message

				if($statusCode -eq 401 -and $oneSuccessfulFetch)
				{
					# Token might have expired! Renew token and try again
					Write-Output "Token might have expired! Renewing token and trying again..."
					
					$authContext = New-Object AuthenticationContext -ArgumentList $authority
					$authResponse = [AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceURI, $ClientID, $uc)
					$authResult = $authResponse.result 
					
					$headers = @{}
					$headers.Add('Authorization','Bearer ' + $authResult.AccessToken)
					$headers.Add('Content-Type', "application/json")
					
					$oneSuccessfulFetch = $False
				}
				elseif($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503)
				{
					# throttled request or a temporary issue, wait for a few seconds and retry
					Write-Output "Possible throttling issues, waiting for few seconds and retrying..."
					Start-Sleep 5
				}
				elseif($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401)
				{
					Write-Output "Please check the permissions of the user"
					break;
				}
				else {
					if ($retryCount -lt 5) {
						Write-Output "Retrying..."
						$retryCount++
					}
					else {
						Write-Output "Download request failed. Please try again in the future."
						break
					}
				}
			 }
			Catch {
			
				# unknown error occured 
				
				$exType = $_.Exception.GetType().FullName
				$exMsg = $_.Exception.Message

				Write-Output "Exception: $_.Exception"
				Write-Output "Error Message: $exType"
				Write-Output "Error Message: $exMsg"

				 if ($retryCount -lt 5) {
					Write-Output "Retrying..."
					$retryCount++
				}
				else {
					Write-Output "Download request failed. Please try again in the future."
					break
				}
				
			} # try-catch

		} while($url -ne $null)

	} # for each request URL

} While ($totime -lt $reportingEndDate)

write-output "End of script."

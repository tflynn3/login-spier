$hostname = $env:computername
 
$startDate = (get-date).AddMinutes(-1)
 
$endDate = get-date

$logs = Get-Eventlog -LogName Security -ComputerName $hostname -after $startDate -before $endDate

$login_users = @()
$accepted_users = "SYSTEM", "$hostname$", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "UpdatusUser"

ForEach ($log in $logs) {

    If ($log.EventID -eq 4624) {

        $login_details = (($log.Message -Split "New Logon:")[1] -Split "Process Information:")[0]
        $user = (($login_details -Split "Account Name:")[1] -Split "Account Domain:")[0].Trim()
        If ( (-not ($user -in $login_users)) -and (-not ($user -in $accepted_users)) ) {
            $login_users += $user

            $messageParameters = @{
            Subject = "User Login: $user"
            Body =  $login_details.Trim()
            From = $from_email
            To = $to_email
            SmtpServer = $smtp_server
            }

            Send-MailMessage @messageParameters
        }
    }
}
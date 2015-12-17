#Comma seperated quoted list of notification Recipients
$recipients = "recepient1@example.com","recipient2@example.com"

#Get the latest lockout event from the Security log
$event = (get-winevent -filterhashtable @{logname="Security";id=4740} -MaxEvents 1 -ComputerName vs-w2k8-pdc).message

#Regex out the locked out user and computer and assign them to $matches, then break those out to usable variables
$matches = ([regex] "(?<=Account Name:\t\t)[a-z]*(?=\r\n)|(?<=Caller Computer Name:\t).*").Matches($event)
$user = $matches[0].Value
$computer = $matches[1].Value

#Create the body of the message and then send the notifications.
$message = "$user was locked out on $computer"
Send-MailMessage -to $recipients -subject "AD Account Locked" -Body $message -From "AD-Notifier@myhorizoncu.com" -SmtpServer mail.myhorizoncu.com

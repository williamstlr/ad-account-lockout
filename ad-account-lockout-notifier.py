#################################################
#This script should be triggered by the Windows	
#task scheduler when it receives an event 4740	
#on the security log.							
#												
#Needs to be run with Administrator Priviliges	
#to query the event manager database.			
#												
#Tyler Williams 								
#August 2015									
#################################################
import subprocess
import re
import smtplib

#Email setup
sender = 'vs-w2k8-pdc@myhorizoncu.com'
receivers = ['tyler@myhorizoncu.com','8013098557@message.ting.com']
subject = "AD Account Lockout"
server = "zmail.myhorizoncu.com"

#The windows event for an AD lockout is 4740, sometimes this will be 4672 for testing
try:
	windowsEvent = subprocess.check_output('wevtutil qe Security "/q:*[System [(EventID=4672)]]" /f:text /rd:true /c:1')
	searchString = re.search('Account Name:.*',windowsEvent)
	lockedUser = (searchString.group(0).split())[2]
	emailMessage = "The following AD account has been locked: %s" %(lockedUser)

except:
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T WARNING  /SO AD-Lockout-Notifier /D "Lockout notification failed to find and parse a username."')
	exit(1)
	
	
try:
	#Setup email server and send the email
	emailServer = smtplib.SMTP(server)
	emailServer.sendmail(sender, receivers, emailMessage)
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T INFORMATION  /SO AD-Lockout-Notifier /D "Notification emails were sent successfully."')
	emailServer.quit()

except:
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T WARNING  /SO AD-Lockout-Notifier /D "Lockout notification failed to send notification emails."')
	exit(1)


exit(0)


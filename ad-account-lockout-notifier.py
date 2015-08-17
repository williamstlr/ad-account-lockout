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
import smtplib,socket
import sys

#Email setup
sender = 'vs-w2k8-pdc@myhorizoncu.com'
receivers = ['tyler@myhorizoncu.com','8013098557@message.ting.com']
subject = "AD Account Lockout"
server = "mail.myhorizoncu.com"

#The windows event for an AD lockout is 4740, sometimes this will be 4672 for testing
try:
        #Search Windows Event log for the last 4740 event and return the value as 'windowsEvent'
	windowsEvent = subprocess.check_output('wevtutil qe Security "/q:*[System [(EventID=4740)]]" /f:text /rd:true /c:1')

	#regex and parse out the username from 'windowsEvent'
	searchUser = re.search(r'(Account Name:\\t\\t(?![vV][sS])[a-zA-Z]*(?!\Add))',str(windowsEvent))
	lockedUser = (re.split(r'\\t', searchUser.group(0)))[2]

	#regex and parse out the computer from 'windowsEvent'
	searchComputer = re.search(r'(Computer Name:\\t\w*)',str(windowsEvent))
	lockedComputer = (re.split(r'\\t',searchComputer.group(1)))[1]

	#create the email message string
	emailMessage = "The following AD account has been locked: %s on computer %s" %(lockedUser,lockedComputer)

except:
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T WARNING  /SO AD-Lockout-Notifier /D "Could not query the Windows Event Log."')
	sys.exit()
	
	
try:
	#Setup email server and send the email
	emailServer = smtplib.SMTP(server)
	emailServer.sendmail(sender, receivers, emailMessage)
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T INFORMATION  /SO AD-Lockout-Notifier /D "Notification emails were sent successfully."')
	emailServer.quit()

except socket.error:
	subprocess.call('eventcreate /ID 1 /L APPLICATION /T WARNING  /SO AD-Lockout-Notifier /D "Could not connect to server to send mail."')
	sys.exit(1)


sys.exit(0)


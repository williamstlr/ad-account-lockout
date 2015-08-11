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
server = "mail.myhorizoncu.com"

#The windows event for an AD lockout is 4740, sometimes this will be 4672 for testing
windowsEvent = subprocess.check_output('wevtutil qe Security "/q:*[System [(EventID=4672)]]" /f:text /rd:true /c:1')
searchString = re.search('Account Name:.*',windowsEvent)
lockedUser = (searchString.group(0).split())[2]
emailMessage = "The following AD account has been locked: %s" %(lockedUser)

#Setup email server and send the email
emailServer = smtplib.SMTP(server)
emailServer.sendmail(sender, receivers, emailMessage)
print "Successfully sent email"
emailServer.quit()

exit(0)


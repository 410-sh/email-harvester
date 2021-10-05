#!/usr/bin/env python

print '''
######################################################################################################
#                                                                                                    #
#  #######                           #     #                                                         #
#  #       #    #   ##   # #         #     #   ##   #####  #    # ######  ####  ##### ###### #####   #
#  #       ##  ##  #  #  # #         #     #  #  #  #    # #    # #      #        #   #      #    #  #
#  #####   # ## # #    # # #         ####### #    # #    # #    # #####   ####    #   #####  #    #  #
#  #       #    # ###### # #         #     # ###### #####  #    # #           #   #   #      #####   #
#  #       #    # #    # # #         #     # #    # #   #   #  #  #      #    #   #   #      #   #   #
#  ####### #    # #    # # ######    #     # #    # #    #   ##   ######  ####    #   ###### #    #  #
#                                                                                                    #  
#                                      Created by: codered072                                        #
######################################################################################################
'''

import smtplib
import time
import imaplib
import email
from email.parser import *
import sys
from fpdf import FPDF
import getpass
import nmap
import pygeoip


mail_username = raw_input('Enter the gmail address: ')
mail_password = getpass.getpass('Enter the password: ')
pdf = FPDF()

scan_prompt = raw_input("Would you like to run a port scan? [y/n] ")

nm = nmap.PortScanner()
#You will need the GeoLiteCity.dat file referenced below to get Geolocation
gi = pygeoip.GeoIP('/PATH/TO/GeoLiteCity.dat')


def CreateTitlePage():
	#Create Report Title Page
	pdf.set_font('Arial', size=32)
	pdf.add_page()
	pdf.cell(200, 235, 'Email Harvester Report', align='C')
	username = raw_input("Name of examiner: ")

	pdf.set_font("Arial", size=10)
	pdf.text(80, 140, str("Report Produced by: "+username)) 


def RunPortScan(ip_addr):
    results = str(nm.scan(ip_addr))
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


def GeoLocation(ip_addr):
	rec = gi.record_by_name(ip_addr)
	city = rec['city']
	if str(city) == 'None':
	    city = 'No Entry'

	country = rec['country_name']
	long = rec['longitude']
	lat = rec['latitude']
	pdf.text(15, 70, str('[*] Target: ' + ip_addr + ' Geo-located.'))
	pdf.text(15,80,str('[*] City: '+str(city)))
	pdf.text(15,90,str('[*] Country: '+str(country)))
	

def deocde_message(email_msg):
    p = Parser()
    message = p.parsestr(str(email_msg))
    decoded_message = ''
    for part in message.walk():
        charset = part.get_content_charset()
        if part.get_content_type() == 'text/plain':
            part_str = part.get_payload(decode=1)
            decoded_message += part_str.decode(charset)
    return decoded_message


def read_email_from_gmail():
    try:
        #Connect to gmail imap server and log into account
        start_time = time.time()
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        print 'Logging into', mail_username
        mail.login(mail_username,mail_password)

        #Load messages in inbox
        print 'Loading inbox...\n'
        mail.select('inbox')
        type, data = mail.search(None, 'ALL')
        mail_ids = data[0]

	print "Generating report..."

        #Search all emails in inbox and return ID list for mailbox
        id_list = mail_ids.split()   
        first_email_id = int(id_list[0])
        latest_email_id = int(id_list[-1])
        cnt = 2
        

        for i in range(latest_email_id,first_email_id, -1):
            #Fetch email with particular ID
            typ, data = mail.fetch(i, '(RFC822)' )
            file_amount = len(id_list) - 1
            for response_part in data:
                #get data from email and load into variables
                if isinstance(response_part, tuple):
                    msg = email.message_from_string(response_part[1])
                    email_subject = msg['subject']
                    email_from = msg['from']
                    email_received = msg['received-spf']
                    email_recvd = str(email_received)
                    email_msg = msg
                    end_time = time.time()
                    total_time = int(end_time - start_time)
                    decoded_message = deocde_message(email_msg)
               	    ip_info = email_received.split(' ')

		    ip_addr = ip_info[6]

		    if scan_prompt == 'y' or scan_prompt == 'yes':
			    RunPortScan(ip_addr)
 
                    #Printing email information
                    total_emails = len(id_list) - 1

                    received_string = 'IP, Date & Time: ' + (email_recvd)
                    email_from4_file = 'From: ' + str(email_from)
                    email_subject4_file = 'Subject: ' + str(email_subject)
                    decoded_message4_file = 'Content of email: ' + decoded_message.encode('utf-8')

                    #For each email, open a new file, increment the name and print the data from the email in the text file
                    pdf.add_page()
		    pdf.text(15, 20, txt=("Email from: " + str(email_from)))
		    pdf.text(15,30, txt=email_subject4_file)
		    pdf.text(15, 40, txt=("IP Address: "+ip_addr))
#		    pdf.text(15, 60, nmap_output[cnt])
		    pdf.text(15,50,txt=(str(decoded_message4_file)))
		    GeoLocation(ip_addr)
		    pdf.text(100,288, txt=('Page: ')+str(cnt)) 
                    cnt += 1

        #Add blank line and display total processing time
        if total_time >= 60:
	    total_time = total_time / 60
            print 'Total Processing time:', total_time, 'minute(s).\n'
	
	else:
  	    print 
            print 'Total Processing time:', total_time, 'second(s).\n'

        #if CTRL C, kill program
    except KeyboardInterrupt:
        print
        print "Process Killed."
        sys.exit(0)

        #if an error, display the error
    except Exception, e:
        print str(e)


CreateTitlePage()
read_email_from_gmail()
pdf.output('FILENAME.pdf', 'F')

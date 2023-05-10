import sys
import geoip2.database
import csv
import PySimpleGUI as sg
import os.path
from os import path
from datetime import datetime
from tqdm import tqdm

# Program version variable
version = 1.4

###### Datafile retrieval to be refreshed from time to time (mainly maxmind data)
# IP comparison: Geolocation/ASN data - https://www.maxmind.com/en/accounts/860125/geoip/downloads
# Naughty list VPN data - https://github.com/X4BNet/lists_vpn (output/vpn/ipv4.txt)
# Naughty list ASN data - https://github.com/brianhama/bad-asn-list
# Naughty list Tor data - https://check.torproject.org/torbulkexitlist

# \\\\\\\\ Naughty list IP data  - https://github.com/stamparm/ipsum

# Update the variable absolute paths below with any name changes

# Creating a variable for strictly the executable to be able to see the database filepaths
databaseexepath = path.abspath(path.join(path.dirname(__file__), 'GeoLite2-City.mmdb'))
asnpath = path.abspath(path.join(path.dirname(__file__), 'GeoLite2-ASN.mmdb'))
badasnpath = path.abspath(path.join(path.dirname(__file__), 'bad-asn-list.csv'))
badvpnnet = path.abspath(path.join(path.dirname(__file__), 'ipv4.txt'))
badtorpath = path.abspath(path.join(path.dirname(__file__), 'torbulkexitlist.txt'))

# Setting the date for later file name use
today = datetime.today()

# Instructions for user
print (f"Binary Lab \nIPGmapper Version {version}")

# Theme for GUI window
sg.theme('Darkblue2')

# Configuring the inside of the window (tabs/text/buttons)
layout = [
    [sg.Text("For Binary Lab use only.", size =(80,1)), sg.Text(f"Version: {version}")],
    [sg.T("")],
    [sg.Text("This program will take a user submmited .CSV file of public IP addresses and output a file with geolocation data of each IP.")],
    [sg.Text("Ensure that the .CSV file has the first column filled only and each row only contains a single IP.")],
    [sg.T("")], [sg.Text("Select the IP list file:", size =(25, 1)), sg.Input(), sg.FileBrowse(key="in1")],
    [sg.Text("Select the output folder path:", size =(25,1)), sg.Input(), sg.FolderBrowse(key="in2")],
    [sg.T("")],
    [sg.Button("Submit"), sg.Button("Cancel")]
          ]

# Set the window name and size, call the layout
window = sg.Window('Binary Lab: IPGmapper', layout, size=(800,270))

# Creating the event of launching the window and setting the input to variables
event, values = window.read()
if event == sg.WIN_CLOSED or event=="Cancel":
    exit()
elif event == "Submit":
    filename = values["in1"]
    folderpath = values["in2"] + '/'
    window.close()

# Inputting the data from the IP file into a list 
file = open(filename)
unformattediplist = list(csv.reader(file, delimiter=","))
iplist = [row[0] for row in unformattediplist]
file.close()

# Create a .CSV to output the data to named with current date/time
timestring = today.strftime('%d.%m.%Y-%S')
outputfilename = 'IPGmapper-' + timestring + '.csv'
outputfilepath = folderpath + outputfilename

# Open new file and add the headers
with open(outputfilepath, 'w', newline='') as outputfile:
    writer = csv.writer(outputfile)
    initialrow = ['IP', 'Country', 'State/Region','City']
    writer.writerow(initialrow)
    print("")


# Loop through IP list to get geolocation data from the database and
# start writing data to file. Failcounter counts the amount of IP's not located
# within the database (aka not public IP's)
# (tqdm is the loop module to show the progress bar,
# reader is expensive to open and must be used before for loop to conserve resources)
    failcounter = 0
    with geoip2.database.Reader(databaseexepath) as reader:
        for ip in tqdm(iplist, desc="location data -> file.. "):
            try:  
                temprowdata = [ip]
                response = reader.city(ip)
                temprowdata.append(response.country.name)
                temprowdata.append(response.subdivisions.most_specific.name)
                temprowdata.append(response.city.name)
                writer.writerow(temprowdata)
            except:
                failcounter += 1
                pass
           
    print("Done..")
    print("")

    # Configuring the inside of another window (tabs/text/buttons) to get user entry on ASN data
    layout = [
    [sg.Text("For Binary Lab use only.", size =(80,1)), sg.Text(f"Version: {version}")],
    [sg.T("")],
    [sg.Text(f"{failcounter} failed IP's. {outputfilename} is located in {folderpath}.")],
    [sg.Text("The next step is to match the IP's to an Autonomous System Number (ASN) database and compare the results")],
    [sg.Text("against an ASN list. This list would mainly include the ASN's of cloud providers who host virtual machines")],
    [sg.Text("that typically should not be making connections to internal resources in most cases.")],
    [sg.T("")], 
    [sg.Text("Do you want to continue and add the ASN data to the output file?")],
    [sg.T("")],
    [sg.Button("Continue"), sg.Button("Cancel")]
          ]

# Set the window name and size, call the layout
    window = sg.Window('Binary Lab: IPGmapper', layout, size=(800,270))

# Creating the event of launching the window and contuning or exiting based on user input
    event, values = window.read()
    if event == sg.WIN_CLOSED or event=="Cancel":
        exit()
    window.close()

# Opening the bad ASN list file
    file1 = open(badasnpath)
    unformattedbadasnlist = list(csv.reader(file1, delimiter=","))
    badasnlist = [row[0] for row in unformattedbadasnlist]

# Read only the IP's that made it through the public IP comparison (refreshing iplist var)
with open(outputfilepath, 'r') as outputfile:
    iplist = [row[0] for row in unformattediplist]
    csv_reader = csv.reader(outputfile)
    rows = list(csv_reader)

# Looping through IP list again and then passing the asn data to the 'compareasn' function to append
# to the asn list
    falsecounter = len(badasnlist)
    print(falsecounter)
    failcounter = 0
    asnlist = ['Bad ASN?']
    with geoip2.database.Reader(asnpath) as reader:
        for ip in tqdm(iplist, desc="ASN data -> file.. "):
            try:  
                response = reader.asn(ip)
                asn = str(response.autonomous_system_number)
                counter = 0
                for x in badasnlist:
                    counter += 1
                    if asn == x:
                        asnlist.append('True')
                        break
                    elif asn != x and falsecounter == counter:                           
                        asnlist.append('False')
            except:
                failcounter += 1
            pass
   # print(failcounter) this one should never fail

### Write temprowdata top -> down to the ASN column in the output file 


for i in range(len(rows)):
    try:
        rows[i][3] = asnlist[i]
    except:
        break

with open(outputfilepath, 'w', newline='') as outputfile:
    csv_writer = csv.writer(outputfile)
    csv_writer.writerows(rows)


file.close()

print("Done..\n")
peacock = input('exit?')
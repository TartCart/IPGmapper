import sys
import geoip2.database
import csv
import PySimpleGUI as sg
import os.path
from os import path
from datetime import datetime
from tqdm import tqdm

# Program version variable
version = 1.2

# Creating a variable for the executable to be able to see the database filepath and
# setting variable to the resource path
databaseexepath = path.abspath(path.join(path.dirname(__file__), 'GeoLite2-City.mmdb'))

# Setting the date for later file name use
today = datetime.today()

# Instructions for user
print (f"Binary Lab \nIPGmapper Version {version}")

# Theme for GUI window
sg.theme('Darkgrey6')

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
with open(outputfilepath, 'w', newline='') as file:
    writer = csv.writer(file)
    initialrow = ['IP', 'Country', 'State/Region','City', 'Postal']
    writer.writerow(initialrow)
    print("")

# Loop through IP list to get geolocation data from the database and
# start writing data to file. Failcounter counts the amount of IP's not located
# within the database.
# (tqdm is the loop module to show the progress bar,
# reader is expensive to open and must be used before for loop to conserve resources)
    failcounter = 0
    with geoip2.database.Reader(databaseexepath) as reader:
        for ip in tqdm(iplist, desc="Writing location data to file.. "):
            try:  
                temprowdata = [ip]
                response = reader.city(ip)
                temprowdata.append(response.country.name)
                temprowdata.append(response.subdivisions.most_specific.name)
                temprowdata.append(response.city.name)
                temprowdata.append(response.postal.code)
                writer.writerow(temprowdata)
            except:
                failcounter += 1
                pass

print("")            
print(f"Done.. {failcounter} IP's failed as they were not public \n{outputfilename} is located in {folderpath}")
print("")
exit = input("Exit?")
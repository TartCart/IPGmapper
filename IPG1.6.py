import geoip2.database
import re
import pandas as pd
import PySimpleGUI as sg
from os import path
from datetime import datetime
from progress.bar import Bar

# Program version variable
version = 1.6

###### Datafile retrieval to be refreshed from time to time (mainly maxmind data)
# IP comparison: Geolocation/ASN data - https://www.maxmind.com/en/accounts/860125/geoip/downloads
# Naughty list VPN data - https://github.com/X4BNet/lists_vpn (output/vpn/ipv4.txt)
# Naughty list ASN data - https://github.com/brianhama/bad-asn-list
# Naughty list Tor data - https://check.torproject.org/torbulkexitlist

# \\\\\\\\ Naughty list IP data  - https://github.com/stamparm/ipsum

# Update the variable absolute paths below with any name changes
# Creating variables strictly for the executable to be able to see the input absolute filepaths
geo_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases\GeoLite2-City.mmdb'))
asn_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases\GeoLite2-ASN.mmdb'))
bad_asn_path = path.abspath(path.join(path.dirname(__file__), 'Databases\\bad-asn-list.csv'))
bad_vpn_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases\ipv4.txt'))
bad_tor_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases\\torbulkexitlist.txt'))
image_path = path.abspath(path.join(path.dirname(__file__), 'Images\BL.ico'))

#### Functions

def clean_input_dfs(input_df):
    pattern = r'([0-9]{1,3}\.){3}[0-9]{1,3}'

    # apply the str.extractall() method to every element of the DataFrame
    ip_addresses = input_df.applymap(lambda x: pd.Series(x).str.extractall(pattern).values)

    # create a new DataFrame with the extracted IP addresses
    clean_df = pd.DataFrame(ip_addresses.sum(), columns=['IP'])

    # display the new DataFrame
    return clean_df

# Add geolocation data to the DF, cull IP's that are not public by removing
# the row in the DF if the function hits an error as it means it does not match the public IP db
def add_geolocation_data(geo_data):
    
    unique_ips = len(geo_data.index)
    print(f"\nDropped duplicate IP's... {unique_ips:,} remaining of the original {total_ip:,}\n")
    cull_count = 0
    cull_ip_list = []
    country_list = []
    region_list = []
    city_list = []
    with geoip2.database.Reader(geo_db_path) as reader:
        with Bar("Culling private IP's and appending location data...", max=unique_ips) as bar:
            for index, row in geo_data.iterrows():
                try:
                    bar.next()
                    ip = row['IP']
                    response = reader.city(ip)
                    country_list.append(response.country.name)
                    region_list.append(response.subdivisions.most_specific.name)
                    city_list.append(response.city.name)
                except:
                    cull_ip_list.append(index)
                    cull_count += 1

    # Adding generated list data to the df
    geo_data = geo_data.drop(index = cull_ip_list)
    final_ip_count = len(geo_data.index)
    print(f"\nDone... {cull_count:,} IP's culled. {final_ip_count:,} total IP's remaining\n")
    geo_data['Country'] = country_list
    geo_data['Region/state'] = region_list
    geo_data['City'] = city_list
    return geo_data

# Check if IP matches VPN data, turn IP into its network address using geo database function
# then compare it against the vpn database
def add_vpn_data(vpn_data):
    
    ip_network_address_list = []
    issue_count = 0
    with geoip2.database.Reader(geo_db_path) as reader:
        with Bar("Matching IP's to VPN database...", max=final_ip_count) as bar:
            for index, row in vpn_data.iterrows():
                try:
                    bar.next()
                    ip = row['IP']
                    response = reader.city(ip)
                    ip_network_address_list.append(response.traits.network)
                except:
                    issue_count += 1
                    pass

    # Turn the generated list of network addresses in to a dataframe for ease of management
    print(f"{issue_count} issues...")
    net_address_df = pd.DataFrame(columns=['network.address'])
    series = pd.Series(ip_network_address_list)
    net_address_df['network.address'] = series

    # Pull in the bad vpn DB
    bad_vpn_df = pd.read_csv(bad_vpn_db_path, names=['network.address'])

    # Checking if the generated network addresses match the vpn network addresses and assigning
    # True/False for VPN data
    true_index_values = net_address_df[net_address_df['network.address'].isin(bad_vpn_df['network.address'])].index.tolist()
    vpn_data['VPN DB'] = vpn_data.index.isin(true_index_values)
    return vpn_data

# Check if IP matches Tor exit point data, basic df to df comparison
def add_tor_data(tor_data):
    
    # Pull in the bad tor DB
    bad_tor_df = pd.read_csv(bad_tor_db_path)
    bad_tor_df.columns = ['ips']
    
    # Checking if the IP addresses match the Tor IP addresses and assigning
    # True/False for Tor data    
    add_index = False
    true_index_list = []
    index_counter = -1
    with Bar("Matching IP's to Tor exit point database...", max=final_ip_count) as bar:
        for index, row in tor_data.iterrows():
            bar.next()
            ip = row['IP']
            if add_index == True:
                true_index_list.append(index_counter)
            index_counter += 1
            for index, row in bad_tor_df.iterrows():
                bad_ip = row['ips']
                if ip == bad_ip:
                    add_index = True
                    break
                elif ip != bad_ip:
                    add_index = False
        if add_index == True:
            true_index_list.append(index_counter)

    # Marking True/False on the final df
    tor_data['TOR DB'] = tor_data.index.isin(true_index_list)
    found_tor_items = len(true_index_list)
    print(f"\nDone... {found_tor_items} Tor exit point matches found")

    return tor_data
   

# Display for the opened shell
print (f"Binary Lab \nIPGmapper Version {version}")

# Theme for GUI window
sg.theme('Darkteal6')

# Configuring the inside of the window (tabs/text/buttons)
layout = [
    [sg.Text("For Binary Lab use only.", size =(80,1)), sg.Text(f"Version: {version}")],
    [sg.T("")],
    [sg.Text("IPGmapper by default takes the submmited .CSV file of public IP addresses and outputs a file with geolocation data for each IP.")],
    [sg.Text("")],
    [sg.T("")],
    [sg.Text("IPGmapper has added functionality of flagging IP's that match against most known addresses for VPNs, Tor exit points,")],
    [sg.Text("ASN data (datacenters - cloud VM providers) and threat intelligence feeds.")],
    [sg.T("")], [sg.Text("Select the input .CSV file:", size =(20, 1)), sg.Input(), sg.FileBrowse(key="in1")],
    [sg.Text("Select the output folder:", size =(20,1)), sg.Input(), sg.FolderBrowse(key="in2")],
    [sg.T(""), sg.Checkbox("Check for common VPN's?", default=False, key="in3")],
    [sg.T(""), sg.Checkbox('Check for Tor exit points?', default=False, key="in4")],
    [sg.T(""), sg.Checkbox('Check for matches on threat intelligence feeds?', default=False, key="in5")],
    [sg.T(""), sg.Checkbox('Check for ASN matches on datacenters?', default=False, key="in6")],
    [sg.T("")],
    [sg.Button("Submit"), sg.Button("Cancel")]
          ]

# Set the window name and size, calling the layout data to the window 
window = sg.Window('IPGmapper', layout, icon = image_path, size=(770,480))

# Launching the window and setting the input to variables
event, values = window.read()
if event == sg.WIN_CLOSED or event=="Cancel":
    exit()
elif event == "Submit":
    input_file_name = values["in1"]
    output_folder_path = values["in2"] + '/'
    if values["in3"] == True:
        check_vpn = True
    else:
        check_vpn = False
    if values["in4"] == True:
        check_tor = True
    else:
        check_tor = False
    if values["in5"] == True:
        check_ti = True
    else: 
        check_ti = False
    if values["in6"] == True:
        check_asn = True
    else:
        check_asn = False
    window.close()


# Inputting the data from the user added .CSV file into a dataframe
# Will try standard encoding for smaller .CSV and then UTF-16 if the file size is too large for standard
try:
    unclean_df = pd.read_csv(input_file_name)
except:
    unclean_df = pd.read_csv(input_file_name, encoding='UTF-16')
total_ip = len(unclean_df.index)

# Removing redundant IP entries
still_unclean_df = unclean_df.drop_duplicates()

# Adding first column name and call functions to add the rest of the data to the DF
still_unclean_df.columns = ['IP']
clean_df = add_geolocation_data(still_unclean_df)
final_ip_count = len(clean_df.index)
if check_vpn == True:
    add_vpn_data(clean_df)
if check_tor == True:
    add_tor_data(clean_df)





# Create and export final .CSV
today = datetime.today()
time_string = today.strftime('%d.%m.%Y-%S')
output_file_name = 'IPGmapper-' + time_string + '.csv'
clean_df.to_csv(output_folder_path + output_file_name, index=False, encoding='utf-8')

# Close file and extro          
print(f"\nSuccess! {output_file_name} is located in {output_folder_path}\n")
input('Exit?')
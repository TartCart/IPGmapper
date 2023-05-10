import geoip2.database
import re
import pandas as pd
import PySimpleGUI as sg
from os import path
from datetime import datetime
from tqdm import tqdm

# Program version variable
version = 1.7

###### Datafile retrieval to be refreshed from time to time (mainly maxmind data) updated 5/8/2023
# IP comparison: Geolocation/ASN data - https://www.maxmind.com/en/accounts/860125/geoip/downloads
# Naughty list VPN data - https://github.com/X4BNet/lists_vpn (output/vpn/ipv4.txt)
# Naughty list ASN data - https://github.com/brianhama/bad-asn-list
# Naughty list Tor data - https://check.torproject.org/torbulkexitlist
# Naughty list threat intelligence data  - https://github.com/stamparm/ipsum

# Update the variable absolute paths below with any name changes
# Creating variables strictly for the executable to be able to see the input absolute filepaths
geo_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases//GeoLite2-City.mmdb'))
asn_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases//GeoLite2-ASN.mmdb'))
bad_asn_path = path.abspath(path.join(path.dirname(__file__), 'Databases//bad-asn-list.csv'))
bad_vpn_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases//ipv4.txt'))
bad_tor_db_path = path.abspath(path.join(path.dirname(__file__), 'Databases//torbulkexitlist.txt'))
image_path = path.abspath(path.join(path.dirname(__file__), 'Images//BL.ico'))

#### Functions
# Combine the multiple input files and fix encoding issues on extremely large data files
def combine_multiple_input_files(multiple_files):
    split_list= multiple_files.split(";")
    multiple_input_dfs = []

    for path in split_list:

        # Will try standard encoding for smaller .CSV and then UTF-16 if the file size is too large and switches to UTF-16 only
        try:
            temp_df = pd.read_csv(path)
        except:
            temp_df = pd.read_csv(path, encoding='UTF-16') 
            try:
                temp_df = pd.read_excel(path)
            except:
                print(f"\nUnable to read input file {path}, ensure files are .CSV, .txt or .xlsx")
                exit()
        
        multiple_input_dfs.append(temp_df)

    # Concatenate all dataframes in the list into a single dataframe
    combined_df = pd.concat(multiple_input_dfs)
    return combined_df

# Remove all excess data from input csv besides unique IP addresses using regex
def clean_input_dfs(input_df):

    # Go through each row of the df and pull out IP's into a list
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = []
    for column in input_df.columns:
        for row in input_df[column]:
            cell_value = str(row)
            ip_address = re.findall(ip_pattern, cell_value)
            ip_addresses.append(ip_address)

    # Add the IP list to the new df 
    ip_addresses = list(filter(None, ip_addresses))
    ip_only = pd.DataFrame(ip_addresses, columns=['IP'])
    total_ip = len(ip_only.index)
    unique_ip_only = ip_only.drop_duplicates()
    unique_ips = len(unique_ip_only)
    ip_difference = total_ip - unique_ips
    print(f"\nDropped {ip_difference} duplicate IP's... {unique_ips:,} remaining of the original {total_ip:,}\n")
    input_df = unique_ip_only
    return input_df

# Add geolocation data to the DF, cull IP's that are not public by removing
# the row in the DF if the function hits an error as it means it does not match the public IP db
def add_geolocation_data(geo_data):
    
    unique_ips = len(geo_data)
    cull_count = 0
    cull_ip_list = []
    country_list = []
    region_list = []
    city_list = []
    ip_network_address_list = []
    asn_list = []
    system_organization = []

    print("Culling non-public IP's, appending location and organization data...")
    with tqdm(total=unique_ips) as pbar:
        for index, row in geo_data.iterrows():
            try:
                pbar.update(1)
                ip = row['IP']
                with geoip2.database.Reader(geo_db_path) as reader:
                    response = reader.city(ip)
                    ip_network_address_list.append(response.traits.network)
                    country_list.append(response.country.name)
                    region_list.append(response.subdivisions.most_specific.name)
                    city_list.append(response.city.name)
                with geoip2.database.Reader(asn_db_path) as reader:
                    response = reader.asn(ip)
                    asn_list.append(response.autonomous_system_number)
                    system_organization.append(response.autonomous_system_organization)
            except:
                cull_ip_list.append(index)
                cull_count += 1

    # Adding generated list data to the df
    geo_data = geo_data.drop(index = cull_ip_list)
    final_ip_count = len(geo_data.index)
    print(f"\nDone... {cull_count:,} IP's culled. {final_ip_count:,} total IP's remaining\n")
    geo_data['Net Address'] = ip_network_address_list
    geo_data['Country'] = country_list
    geo_data['Region/state'] = region_list
    geo_data['City'] = city_list
    geo_data['Organization'] = system_organization
    geo_data['ASN'] = asn_list
    return geo_data

# Check if IP matches VPN data, turn IP into its network address using geo database function
# then compare it against the vpn database
def add_vpn_data(vpn_data):
    
    # Pull in the bad vpn DB
    bad_vpn_df = pd.read_csv(bad_vpn_db_path, names=['network.address'])   

    # Match data
    vpn_data['VPN DB'] = vpn_data['Net Address'].isin(bad_vpn_df['network.address'])
    return vpn_data

# Check if IP matches Tor exit point data, basic df to df comparison
def add_tor_data(tor_data):
    
    # Pull in the bad tor DB
    tor_df = pd.read_csv(bad_tor_db_path, names=['ips'])
    
    # Checking if the IP addresses match the Tor IP addresses and assigning True/False for Tor data  
    tor_data['Tor DB'] = tor_data['IP'].isin(tor_df['ips'])

    return tor_data
 
# Download latest ti feed IP's and match data
def add_ti_data(ti_data):

    # Get the latest threat intelligence IP list, turn it into a df
    try:
        ti_url = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
        ti_df = pd.read_csv(ti_url, sep='delimeiter', header=None, engine='python')
    except:
        print("Cannot reach Threat Intelligence URL, exiting...")
        exit()

    # Pull out IP's from the ti df 
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ti_ip_addresses = []
    for column in ti_df.columns:
        for row in ti_df[column]:
            cell_value = str(row)
            ip_address = re.findall(ip_pattern, cell_value)
            ti_ip_addresses.append(ip_address)

    # Create new df from list, drop empty entries  and reset index to reflect true entries
    ti_ip_df = pd.DataFrame(ti_ip_addresses, columns=['ips'])
    ti_ip_df_dropped_empties = ti_ip_df.dropna(how='all')
    ti_ip_df_final = ti_ip_df_dropped_empties.reset_index(drop=True)

    # Checking if the IP addresses match the TI IP generated df 
    ti_data['TI DB'] = ti_data['IP'].isin(ti_ip_df_final['ips'])

    return ti_data

# Check if ASN data matches bad ASN list
def check_asn(asn_data):
    bad_asn_df = pd.read_csv(bad_asn_path, names=['bad_asn_column'])

# GUI window display and theme color
print (f"Binary Lab \nIPGmapper Version {version}")
sg.theme('Darkteal6')

# Configuring the inside of the window (tabs/text/buttons)
layout = [
    [sg.Text("For Binary Lab use only.", size =(80,1)), sg.Text(f"Version: {version}")],
    [sg.T("")],
    [sg.Text("IPGmapper by default takes the submmited .CSV files and outputs a file with geolocation data for each IP.")],
    [sg.Text("Adding multiple files at once is supported along with raw log files that may have additional data other than IP's")],
    [sg.T("")],
    [sg.Text("IPGmapper has added functionality of flagging IP's that match against suspicious addresses for VPNs, Tor exit points,")],
    [sg.Text("ASN data (datacenters - cloud VM providers) and threat intelligence feeds.")],
    [sg.Text("*Selecting all checks will drastically slow down processing time for large files*")],
    [sg.T("")], 
    [sg.Text("     Select the input .CSV file(s):", size =(26, 1)), sg.Input(), sg.FilesBrowse(key="in1")],
    [sg.Text("     Select the output folder:", size =(26,1)), sg.Input(), sg.FolderBrowse(key="in2")],
    [sg.Text("     You can prepend the output filename below, leave blank for the default format")],
    [sg.T(""), sg.Input(key="in8")],
    [sg.T(""), sg.Checkbox('Do you want to create two separate output files, splitting foreign and domestic data?', default=False, key="in7")],
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
    user_prepend = values["in8"]
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
    if values["in7"] == True:
        separate_files = True
    else:
        separate_files = False
    window.close()

#### Run through functions to clean the final dataframe and generate data based on the IP list and user selections
# Combing the input files into one dataframe
combined_df = combine_multiple_input_files(input_file_name)

# Cleaning up input file leaving only unique IP addresses behind
clean_df = clean_input_dfs(combined_df)

# Appending data 
final_df = add_geolocation_data(clean_df)
final_ip_count = len(final_df.index)
if check_vpn == True:
    add_vpn_data(final_df)
if check_tor == True:
    add_tor_data(final_df)
if check_ti == True:
    add_ti_data(final_df)
if check_asn == True:
    check_asn(final_df)

# Sort the final data and create separate output(names) files if the user chose that option
final_df.sort_values(by='Country', inplace=True, ascending=True)
filtered_user_prepend = ''.join([char for char in user_prepend if char.isalpha()])
if user_prepend != filtered_user_prepend:
    print('Bad format for user prepended filename.. fixing..\n')
    user_prepend = filtered_user_prepend

if user_prepend == '':
    if separate_files == True:
        domestic_df_filtered = final_df[final_df['Country'] == 'United States']
        international_df_filtered = final_df[final_df['Country'] != 'United States']
        today = datetime.today()
        time_string = today.strftime('%m.%d.%y-%M')
        output_file_name = 'IPG.' + time_string

        domestic_df_filtered.to_csv(output_folder_path + output_file_name + '.domestic.csv', index=False, encoding='utf-8')
        international_df_filtered.to_csv(output_folder_path + output_file_name + '.foreign.csv', index=False, encoding='utf-8')
    else:
    # Create and export final .CSV without separation
        today = datetime.today()
        time_string = today.strftime('%m.%d.%y-%M')
        output_file_name = 'IPG' + time_string + '.csv'
        final_df.to_csv(output_folder_path + output_file_name, index=False, encoding='utf-8')
else:
    if separate_files == True:
        domestic_df_filtered = final_df[final_df['Country'] == 'United States']
        international_df_filtered = final_df[final_df['Country'] != 'United States']
        today = datetime.today()
        time_string = today.strftime('%m.%d.%y-%M')
        output_file_name = user_prepend + '.' + time_string

        domestic_df_filtered.to_csv(output_folder_path + output_file_name + '.domestic.csv', index=False, encoding='utf-8')
        international_df_filtered.to_csv(output_folder_path + output_file_name + '.foreign.csv', index=False, encoding='utf-8')
    else:
    # Create and export final .CSV without separation
        today = datetime.today()
        time_string = today.strftime('%m.%d.%y-%M')
        output_file_name = user_prepend + '.' + time_string + '.csv'
        final_df.to_csv(output_folder_path + output_file_name, index=False, encoding='utf-8')

# Extro          
print(f"\nSuccess! The exported .CSV file is located in {output_folder_path}\n")
input('Exit?')
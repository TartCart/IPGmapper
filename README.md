# IPGmapper
.exe for providing geolocation and other data from raw log IP files written in Python

Create venv in your repository  
install packages below  
run pyinstaller to create the .exe  
`pyinstaller -F --add-data="GeoLite2-City.mmdb;." --add-data="GeoLite2-ASN.mmdb;." --add-data="BL.ico;." -n IPGmapper  .\IPG1.7.py`

requirements: 

city and ASN database files from maxmind - GeoLite2-City.mmdb - GeoLite2-ASN.mmdb


from `pip list`   
to install do `pip install %package%`
```
Package                   Version
------------------------- --------
aiohttp                   3.8.4   
aiosignal                 1.3.1   
altgraph                  0.17.3  
async-timeout             4.0.2   
attrs                     23.1.0  
certifi                   2023.5.7
charset-normalizer        3.1.0   
colorama                  0.4.6   
frozenlist                1.3.3   
geoip2                    4.7.0   
idna                      3.4
maxminddb                 2.3.0
multidict                 6.0.4
numpy                     1.24.3
pandas                    2.0.1
pefile                    2023.2.7
pip                       23.1.2
pyinstaller               5.11.0
pyinstaller-hooks-contrib 2023.3
PySimpleGUI               4.60.4
python-dateutil           2.8.2
pytz                      2023.3
pywin32-ctypes            0.2.0
requests                  2.30.0
setuptools                65.5.0
six                       1.16.0
tqdm                      4.65.0
tzdata                    2023.3
urllib3                   2.0.2
yarl                      1.9.2
```

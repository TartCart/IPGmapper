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
Package            Version
------------------ --------
aiohttp            3.8.4
aiosignal          1.3.1
async-timeout      4.0.2
attrs              23.1.0
certifi            2023.5.7
charset-normalizer 3.2.0
colorama           0.4.6
frozenlist         1.3.3
geoip2             4.7.0
idna               3.4
ipaddress          1.0.23
maxminddb          2.4.0
multidict          6.0.4
numpy              1.25.1
pandas             2.0.3
pip                23.1.2
PySimpleGUI        4.60.5
python-dateutil    2.8.2
pytz               2023.3
requests           2.31.0
setuptools         65.5.0
six                1.16.0
tqdm               4.65.0
tzdata             2023.3
urllib3            2.0.3
yarl               1.9.2
```

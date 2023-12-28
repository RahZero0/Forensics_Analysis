# Forensics_Analysis
 Work in progress...

pre-requesits
download the file https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
to the location volatility3\symbols

first 
run this code after extracting the files:
python runner.py
-- this is to install all the dependancies

then 
run the code
python .\vol.py -f volatility3\plugins\memdump.mem -r json windows.modules
-- this is to create a cache dump setting

then 
run the code
python apple.py
-- this is to commence the process of gathering the RAM info and then using it for analysis

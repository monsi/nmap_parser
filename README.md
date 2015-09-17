# nmap_parser

After not being able to find an Nmap parser I liked, I decided to write my own.
The script is simple but hopefully works for your needs.

Some of the capabilities of the script are as follows:

1. List ALL nse's that were reported by Nmap ( just use -f [filename]; xml files only )
2. List All nse's for a particular host ( -t [host] )
3. List All hosts with a specific nse ( -n [nse; ssl-enum-ciphers, etc...] )
4. Display specific nse output for a specific host ( -n [nse] -t [host] )
5. List All nse's identified as "VULNERABLE" by Nmap ( -v )
6. List All nse id's found within the xml file ( -l )


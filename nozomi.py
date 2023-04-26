#!/usr/bin/python3
# usage: python3 nozomi.py 
# verbose: python3 nozomi.py -v yes
# manual run example using a list: python3 nozomi.py -l nozomiList.txt -e 1681403833000 
# manual run example using a single host: python3 nozomi.py -n hostname.com -e 1681403833000 
# manual run example using credentials: python3 nozomi.py -n hostname.com -e 1681403833000 -u myUser -p 'myPass'
# list file must be in FQDN format
# enclose passwords in single quotes (not double)
# epoch time must be in millisecond format
# can only use -l or -n but not both
#
## edit the below fields to skip command line parameters.  epoch and hostname are optional
muser = "username"
mpassword = "password"
moutputFolder = "/path/to/folder"
mlistFile = "/home/splunk/list.txt"
interval = 30       ## last N minutes of logs from host.  use this interval to run the cron task
mepoch=None
mhostname = None
verbose = 0
### no edits below this line
user=None;password=None;epoch=None;hostname=None;outputFolder=None;listFile=None;hostShort=""
import requests, os, subprocess, json, datetime, time, os.path, pdb, argparse, glob, sys, socket
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests.auth import HTTPBasicAuth
from urllib.error import HTTPError
from requests.exceptions import RequestException
import socket
from socket import AF_INET, SOCK_DGRAM
############################################
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "verbose output", required=False )
parser.add_argument("-u", "--user", help = "username", required=False )
parser.add_argument("-p", "--password", help = "password of user account", required=False )
parser.add_argument("-l", "--listFile", help = "list file to use", required=False )
parser.add_argument("-e", "--epoch", help = "epoch time", required=False )
parser.add_argument("-n", "--hostname", help = "hostname of device.  leave blank for all", required=False )
args = parser.parse_args()
############################################
if args.verbose:
    verbose=args.verbose.lower()
    print("Diplaying verbose entered as: % s" % args.verbose)
    print("Diplaying user entered as: % s" % args.user)
    print("Diplaying password entered as: % s" % args.password)
    print("Diplaying listFile entered as: % s" % args.listFile)
    print("Diplaying epoch entered as: % s" % args.epoch)
    print("Diplaying hostname entered as: % s" % args.hostname)
############################################
if args.user:
    user=args.user
if args.password:
    password=args.password
if args.epoch:
    epoch=args.epoch
if args.hostname:
    hostname=args.hostname
if args.listFile:
    listFile=args.listFile
####
if args.hostname and args.listFile:
    sys.exit("Can't use both -l and -n parameters!  Quitting.")
if user is None:
    user = muser
if password is None:
    password = mpassword
if hostname is None or str(hostname) == "":
    hostname = mhostname
if epoch is None:
    epoch = mepoch
if listFile is None:
    listFile = str(mlistFile)
if outputFolder is None: 
    outputFolder = moutputFolder
############################################
if verbose == "yes" or verbose == "1":
    verbose = 1
else:
    verbose = int(verbose)
    print ('debug = ',verbose)
    print ('Number of arguments:', len(sys.argv), 'arguments.')
    print ('Argument List:', str(sys.argv))
############################################
def pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam):
    max = 10000
    URL = "https://"+str(hostname)+"/api/open/query/do?query="+str(query)+"%20%7C%20where%20"+str(timeparam)+"%20%3E%20"+str(tgtEepoch)+"%20%7C%20sort%20"+str(timeparam)+"%20asc%20%7C%20head%20"+str(max)
    if verbose == 2:
        print("URL for "+str(query)+" events: "+str(URL))
    PARAMS = {'username':user, 'password': password }
    try:
        req = requests.get(url = URL, auth=HTTPBasicAuth(user, password), verify=False)
        req.raise_for_status()
        res = req.json()
        data = json.dumps(res["result"])
        if "." in str(hostname):
            hostShort = hostname.split(".")
            hostShort = str(hostShort[0])
        # check for empty hostname and add it if needed
        data = data.replace('"appliance_host": ""','"appliance_host": "'+str(hostShort)+'"')
        data = data.replace('"appliance_host": null','"appliance_host": "'+str(hostShort)+'"')
        if verbose != 0:
            print("total "+str(query)+" recieved: "+str(res["total"]))
        if int(res["total"]) > 0:
            if verbose == 2:
                print("writing "+str(res["total"])+" events to file: "+str(outputFile))
            f=open(outputFile, 'a') ## 'a' creates if not exist
            f.write(data)
            f.close()
    except requests.exceptions.ConnectionError as err:
        #raise SystemExit(err)
        print(err)

f=open(listFile, 'r')
read = f.read()
f.close()
myList = read.split("\n")
myList = sorted(myList)
nowTime = datetime.datetime.now()
nowTime = str(nowTime.strftime('%c'))
interval = int(interval)
if not os.path.exists(outputFolder):
    os.system('mkdir -p '+str(outputFolder))
if hostname is not None:
    myList = [ hostname ]
if epoch is None:
    # get last 30m of data - this should match the crontab iteration
    tgtEepoch = datetime.datetime.now() - datetime.timedelta(minutes=interval)
    tgtEepoch = str(tgtEepoch.strftime('%s'))+"000"
    if verbose != 0:
        print("tgtEpoch: "+str(tgtEepoch))
else:
    tgtEepoch = str(epoch)
x=0
while(x<len(myList) ):
    if "#" in str(myList[x]):
        if verbose != 0:
            print(str(hostname)+" is disabled.  skipping.")
    elif str(myList[x]) == "":
        print("value at "+str(x)+" is empty, skipping")
    else:
        ## test by pulling only 1 alert
        hostname = myList[x].replace(" ","")
        URL = "https://"+str(hostname)+"/api/open/query/do?query=alerts%20%20%7C%20where%20created_time%20%3E%20"+str(tgtEepoch)+"%20%7C%20sort%20created_time%20asc%20%7C%20head%201"
        if verbose != 0:
            print("testing '"+str(myList[x])+"'\nURL: "+str(URL)+"")
        PARAMS = {'username':user, 'password': password }
        errMsg = ""; aaa = "timed out"
        try:
            aaa = requests.get(url = URL, auth=HTTPBasicAuth(user, password), verify=False, timeout=3)
        except requests.exceptions.ConnectionError as errMsg:
            print(str(errMsg))
        except HTTPError as errMsg:
            print(str(errMsg))
        except socket.timeout as errMsg:
            print(str(errMsg))
        except RequestException as errMsg:
            print(str(errMsg))
        if str(aaa) != "<Response [200]>" or str(errMsg) != "":
            text = str(hostname)+" test failed, skipping. --> "+str(aaa)
            print(text)
        else:
            text = hostname+" SUCCESS >> "+str(aaa)
            if verbose != 0:
                print(text)
            print("starting "+str(hostname))
            ## alerts
            timeparam = "created_time"
            query="alerts"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## node_cpe_changes 
            query="node_cpe_changes"
            timeparam = "time"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## assets 
            query="assets"
            timeparam = "last_activity_time"
            #timeparam = "created_at"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## node_cpes 
            query="node_cpes"
            timeparam = "time"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## node_cves
            query="node_cves"
            timeparam = "cve_update_time"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## health logs
            timeparam = "time"
            query="health_log"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## assertions
            timeparam = "time"
            query="assertions"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## link events
            timeparam = "time"
            query="link_events"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## node points
            timeparam = "time"
            query="node_points"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## captured urls
            timeparam = "time"
            query="captured_urls"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## links
            timeparam = "last_activity_time"
            query="links"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )
            ## variables
            timeparam = "last_update_time"
            query="variables"
            outputFile = outputFolder + "/"+str(hostname)+"-"+str(query)+".log"
            pull(hostname, query, tgtEepoch, user, password, outputFile, timeparam )

    x=x+1
os.system("sudo find /data1/syslog-ng/nozomi/ -empty  -exec rm -f {} \;")

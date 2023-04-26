This script was written to replace the current nozomi-splunk addon provided by nozomi (TA-nozomi-networks-addon).  The current version of the nozomi addon uses an individual python process for EACH input and each data type.   Because the addon doesnt consolidate CPU, an org with many nozomi guardian devices will find their server becoming quite unstable very quickly.  In most cases, our server failed to run many of the inputs as well as other addons and scripts on that server.  So I wrote this to loop through all the inputs using the same API commands in use by the addon.  <br><br>

INSTALL: <br>
copy the nozomi.py file to a location on your linux server.  edit the file and fill in the fields at the top (username, password, outputFolder, listFile).  If you have git installed, you can use git clone with the repo url. <br><br>
<ul>
  <li>Username & password are credentials for a user account on the nozomi guardian</li>
  <li>outputFolder is the location where the script will place the data is has collected from the nozomi guardians</li>
  <li>listFile is the file that contains a line separated list of FQDN hostnames of the nozomi devices (eg.  myHostname.com)</li>
  </ul>
  <br><br>
With the above information, you should be ready to test the script:<br>
# python3 nozomi.py -v yes<br><br>

If everything works as expected without errors, create a cron job withtout the -v parameter to run the script every 30 minutes or the number of minutes you defined with the 'interval' parameter.  <br><br>
If you see lots of errors, run with '-v 2' to see all of the URLs it's using.  Test them on postman to confirm.  Verify connectivity to the nozomi devices and verify the account works.  <br><br>
The script will go through the list of devices and gather the various types of data one by one, then move to the next hostname on the list.   If you don't want certain types of data, you can just comment out the call to the pull() function as needed.   <br><br>
You can run the script manually with the various paramter flags as defined in the notes at the beginning of the file.<br><br>
When your data is writing to the folder, setup a splunk input to monitor as needed.<br>

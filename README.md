wp-update-server-guardian
=========================

 

An example of a man in the middle gateway for use with
https://github.com/YahnisElsts/wp-update-server this isn’t production ready but
does allow the use of additional checking for authorization, you could for
example rewrite the API key to work with a licencing server only passing on the
details if they pass.

 

Why Man in the middle? Well the idea for me was that by doing it this way a) i
don’t expose the update server directly in the plugin files and b) it allows me
to write what I want without having to modify the actual wp-update-server files,
they serve as usual.

 

Within Plugin Usage:
--------------------

Modify your PucFactory::buildUpdateChecker for example so it includes an API key
and example is given below

`$custom_server_url .
'?key=XXXXXXXXXXXXXYYYYYYYXXXXXXXX&?action=get_metadata&slug=' .
$plugin_data['TextDomain'],`

The added `?key=XXXXXXXXXXXXXYYYYYYYXXXXXXXX&` is excluded when the guardian
pulls the data on authentication from the actual real update server

 

You could for example pull this “key” from the WPoptions table and append that
variable there

 

Setup
-----

Install the files within the REPO and make the required modifications and you
are ready to begin “man in the middle” delivery immediately

 

### Index.php

This is the main file and you need to decide on some options here but they are
all set within the head of the file

`// Configuration`

`$real_update_server_url = 'https://exampledomain.com/updates/'; // Replace with
your real server URL where https://github.com/YahnisElsts/wp-update-server in
installed i.e exampledomain.com/updates/`

`$api_keys_file = __DIR__ . '/api-keys.conf';`

`$whitelist_file = __DIR__ . '/whitelist.conf';`

`$blacklist_file = __DIR__ . '/blacklist.conf';`

`$bypass_file = __DIR__ . '/bypass.conf';`

`$log_dir = __DIR__ . '/logs'; // Directory for logs`

`$enable_api_key_check = true; // Switch to enable/disable API key check`

`$enable_whitelist_check = true; // Switch to enable/disable whitelist check`

`$enable_blacklist_check = true; // Switch to enable/disable blacklist check`

`$enable_bypass = false; // Switch to enable/disable bypass checking`

`$whitelist_check_mode = 'or'; // Set to 'and' or 'or' to control whitelist
logic`

 

This is the most basic of checks do we want to check for api-key / licence keys
`$enable_api_key_check = true;` All these true means on false means off.

  
White List: means we are checking a domain or ip is on the list

Black List : NO ACCESS at all for this domain / IP

Bypass: Add Domains / IPs where an API check doesn’t happen, allows you to use
just domains or ips rather than just API or API and Whitelist

  
API-key: This is where your API / Licence Keys would be stored.

 

**I recommend moving the conf files & logs BELOW http:// or htdocs for better
security**

 

### Conf Files:

 

All Conf Files are designed to be able to take comments with either // or \#\#
to explain and give you future details of what they are for example

  


`0.0.0.0 ## Example IP`

`somedomain.com // Example Domain`

 

Each Conf File contains an example of an acceptable line for using i.e domain /
ip or anything for api-keys

 

### Logs

Logs should automatically delete every 30 days and logs look like this

 

Date / Time Ip Referer Domain Status and additional information

 

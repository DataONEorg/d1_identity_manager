Configuring OpenLDAP
--------------------
-Install OpenLDAP (v2.4) if not already in place
	
-I'm still choosing to use the slapd.conf mechanism for configuring OpenLDAP
	-it is easier to see a snapshot of the configuration
	-you can always revert to a saved copy of it if things go sour
-Use the slapd.conf.template file as a starting point for your server's configuration:
	/etc/ldap/slapd.conf
	-If you are using the default dataone tree, then you should only have to worry about specifying the admin password
	-If you are setting up 2 (or more) replicas, you should pay attention to the "syncRepl" section and the server hostnames should be filled in correctly
	-repeat these instructions for each replica, making sure each replica has a unique "serverID" (see template)
-Place the dataone.schema file in the the ldap schema extension directory:
	/etc/ldap/schema/dataone.schema	
-Start slapd, pointing it to the configuration file
	slapd -h 'ldap:/// ldapi:///' -f /etc/ldap/slapd.conf
	-Note: /etc/init.d/slapd start will attempt to use the newer database-based configuration method so you should not use that until we finalize configuration and convert the .conf to the db method
-Populate the root of the dataone.org tree by adding the ldif:
	ldapadd -D cn=admin,dc=dataone,dc=org -W -H ldap://<YOUR_HOST_NAME>:389 -x -f dataone.ldif
-Check the entries for the dataone.org tree:
	ldapsearch -LLL -D cn=admin,dc=dataone,dc=org -W -H ldap://<YOUR_HOST_NAME:389 -x -b 'dc=dataone,dc=org'		
	
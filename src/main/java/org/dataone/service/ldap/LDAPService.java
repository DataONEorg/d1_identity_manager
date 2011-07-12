package org.dataone.service.ldap;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.configuration.Settings;
import org.dataone.service.types.Subject;


/**
 * Base LDAP class for shared LDAP operations
 * Intended to be used by the Identity Manager and the Identifier Reservation systems
 * 
 * @author leinfelder
 *
 */
public class LDAPService {
	
	public static Log log = LogFactory.getLog(LDAPService.class);
	
	protected DirContext context = null;
	
	// look up defaults from configuration
	protected String server = Settings.getConfiguration().getString("identity.ldap.server");
	protected String admin = Settings.getConfiguration().getString("identity.ldap.admin");
	protected String password = Settings.getConfiguration().getString("identity.ldap.password");
	protected String base = Settings.getConfiguration().getString("identity.ldap.base");

	public DirContext getContext() throws NamingException {
		if (context == null) {
			context = getDefaultContext();
		}
	    return context;
	}
	
	protected DirContext getDefaultContext() throws NamingException {
		Hashtable<String, String> env = new Hashtable<String, String>();
	    /*
	     * Specify the initial context implementation to use.
	     * This could also be set by using the -D option to the java program.
	     * For example,
	     *   java -Djava.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory \
	     *       Modattrs
	     */
	    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	    /* Specify host and port to use for directory service */
	    env.put(Context.PROVIDER_URL, server);
	    /* specify authentication information */
	    env.put(Context.SECURITY_AUTHENTICATION, "simple");
	    env.put(Context.SECURITY_PRINCIPAL, admin);
	    env.put(Context.SECURITY_CREDENTIALS, password);

        /* get a handle to an Initial DirContext */
        DirContext ctx = new InitialDirContext(env);
	    return ctx;
	}
	
	
	public String getServer() {
		return server;
	}

	public void setServer(String server) {
		this.server = server;
	}

	public String getAdmin() {
		return admin;
	}

	public void setAdmin(String admin) {
		this.admin = admin;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean removeEntry(String dn) {
		try {
			DirContext ctx = getContext();
			ctx.destroySubcontext(dn);
	    	log.debug("Removed entry: " + dn);
	    } catch (NamingException e) {
	    	log.error("Error removing entry: " + dn, e);
	        return false;
	    }
	    
	    return true;
	}
	
	// check the attribute for a given subject
	public boolean checkAttribute(Subject subject, String attributeName, String attributeValue) {
		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
		    ctls.setReturningAttributes(new String[0]);  // do not return any attributes
		    
		    String searchCriteria = attributeName + "=" + attributeValue;
		    
	        NamingEnumeration results = 
	            ctx.search(subject.getValue(), searchCriteria, ctls);
	        
	        boolean result = (results != null && results.hasMoreElements());
	        if (result) {
	        	log.debug("Found matching attribute: " + searchCriteria);
	        } else {
	        	log.warn("Did not find matching attribute: " + searchCriteria);
	        }
	        return result;
	    } catch (NamingException e) {
	    	log.error("Problem checking attribute: " + attributeName, e);
	    }
	    return false;
		
	}
	
	protected String parseAttribute(String original, String attribute) {
		String result = null;
		try {
			String temp = original;
			temp = temp.substring(temp.indexOf( attribute + "="), temp.indexOf(","));
			temp = temp.substring(temp.indexOf("=") + 1) ;
			result = temp;
		} catch (Exception e) {
			log.warn("could not parse attribute from string");
		}
		return result;
	}
	
	public static void main(String[] args) {
		try {
			
			String dn = "cn=test1,dc=dataone,dc=org";
		
			LDAPService identityService = new LDAPService();
//			identityService.setServer("ldap://bespin.nceas.ucsb.edu:389");
			identityService.removeEntry(dn);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

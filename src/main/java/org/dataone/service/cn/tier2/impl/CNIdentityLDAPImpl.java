package org.dataone.service.cn.tier2.impl;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.service.cn.tier2.CNIdentity;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.AuthToken;
import org.dataone.service.types.Person;
import org.dataone.service.types.Principal;


/**
 * Proposed LDAP schema extensions
 * 
 * objectClass: d1Principal
 * attributes:
 * 		equivalentIdentity (0...n) - used when mapping is confirmed
 * 		equivalentIdentityRequest (0...n) - used when mapping is requested (before confirmation)
 * 		isVerified (1...1) - used when untrusted account is registered
 * 
 * objectClass: d1Group
 * attributes:
 * 		adminIdentity (0...n) - references other Principals that are allowed to modify the group 
 * 
 * @author leinfelder
 *
 */
public class CNIdentityLDAPImpl implements CNIdentity {
	
	public static Log log = LogFactory.getLog(CNIdentityLDAPImpl.class);
	
	// TODO: parameterize or configure somewhere else
	private String server = "ldap://fred.msi.ucsb.edu:389";
	private String admin = "cn=admin,dc=dataone,dc=org";
	private String password = "password";
	
	public boolean confirmMapIdentity(AuthToken token1, AuthToken token2)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean createGroup(Principal groupName) throws ServiceFailure,
			InvalidToken, NotAuthorized, NotFound, NotImplemented,
			InvalidRequest, IdentifierNotUnique {
		
		// Values for the entry
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("groupOfUniqueNames");
	    objClasses.add("d1Group");
	    Attribute cn = new BasicAttribute("cn", parseAttribute(groupName.getValue(), "cn"));
	    // 'uniqueMember' is required - so no empty groups!
	    Attribute uniqueMember = new BasicAttribute("uniqueMember", "");
	    // TODO: need the Principal who created the group (will be in cert)
	    Attribute adminIdentity = new BasicAttribute("adminIdentity", "");
	    // the DN for the group
	    String dn = groupName.getValue();
	   
	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        orig.put(cn);
	        orig.put(uniqueMember);
	        orig.put(adminIdentity);
	        ctx.createSubcontext(dn, orig);
	        log.debug( "Created group " + dn + ".");
	    } catch (NameAlreadyBoundException e) {
	        /* If entry exists already, fine.  Ignore this error. */
	    	log.warn("Group " + dn + " already exists, no need to create");
	        //return true;
	    } catch (NamingException e) {
	    	log.error("Problem creating group." + e);
	        return false;
	    }
	    
		return true;
	}
	
	// TODO: must override the interface method!
    public boolean addGroupMembers(Principal groupName, List<Principal> members) 
    	throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {
    	
    	try {
	        // context
	        DirContext ctx = getContext();
	        
	        // TODO: check that they have admin rights for group
	        
	        for (Principal principal: members) {
		        // TODO: check that they are not already a member

		        // add them as a member
		        ModificationItem[] mods = new ModificationItem[1];
		        Attribute mod0 = new BasicAttribute("uniqueMember", principal.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(groupName.getValue(), mods);
		        log.debug("Added member: " + principal.getValue() + " to group: " + groupName.getValue() );
	        }
	    } catch (NamingException e) {
	        throw new ServiceFailure(null, e.getMessage());
	    }
    	
    	return true;
    	
    }

	public boolean mapIdentity(Principal primaryPrincipal, Principal secondaryPrincipal)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

		try {
	        // get the context
	        DirContext ctx = getContext();
	        
	        // check if primary is confirming secondary
	        boolean confirmationRequest = 
	        	checkAttribute(primaryPrincipal, "equivalentIdentityRequest", secondaryPrincipal.getValue());
	        
	        ModificationItem[] mods = null;
	        Attribute mod0 = null;
	        if (confirmationRequest) {
		        // update attribute on primaryPrincipal
		        mods = new ModificationItem[2];
		        mod0 = new BasicAttribute("equivalentIdentity", secondaryPrincipal.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // remove the request from primary since it is confirmed now
		        Attribute mod1 = new BasicAttribute("equivalentIdentityRequest", secondaryPrincipal.getValue());
		        mods[1] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod1);
		        // make the change
		        ctx.modifyAttributes(primaryPrincipal.getValue(), mods);
		        log.debug("Successfully set equivalentIdentity: " + primaryPrincipal.getValue() + " = " + secondaryPrincipal.getValue());
		    
		        // update attribute on secondaryPrincipal
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", primaryPrincipal.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondaryPrincipal.getValue(), mods);
		        log.debug("Successfully set reciprocal equivalentIdentity: " + secondaryPrincipal.getValue() + " = " + primaryPrincipal.getValue());
	        } else {
	        	// mark secondary as having the equivalentIdentityRequest
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentityRequest", primaryPrincipal.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondaryPrincipal.getValue(), mods);
		        log.debug("Successfully set equivalentIdentityRequest on: " + secondaryPrincipal.getValue() + " for " + primaryPrincipal.getValue());
		    
	        }
	        
		} catch (NamingException e) {
			e.printStackTrace();
	        return false;
	    }		
		
		return true;
	}

	public boolean verifyAccount(Principal principal) throws ServiceFailure,
			NotAuthorized, NotImplemented, InvalidToken, InvalidRequest {
		
	    try {
	        /* get a handle to an Initial DirContext */
	        DirContext ctx = getContext();
	        
	        /* construct the list of modifications to make */
	        ModificationItem[] mods = new ModificationItem[1];
	        // Update isVerified attribute
		    Attribute isVerified = new BasicAttribute("isVerified", Boolean.TRUE.toString().toUpperCase());
	        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, isVerified);
	        
	        /* make the change */
	        ctx.modifyAttributes(principal.getValue(), mods);
	        log.debug( "Verified principal: " + principal.getValue() );
	    } catch (NamingException e) {
	        throw new ServiceFailure(null, e.getMessage());
	    }		
		
		return true;
	}

	public Principal registerAccount(Person p) {
	    // Values we'll use in creating the entry
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("person");
	    objClasses.add("organizationalPerson");
	    objClasses.add("inetOrgPerson");
	    objClasses.add("d1Principal");
	    Attribute cn = new BasicAttribute("cn", p.getFamilyName());
	    // TODO handle actual name if we have it
	    Attribute sn = new BasicAttribute("sn", p.getFamilyName());
	    Attribute givenNames = new BasicAttribute("givenname", p.getGivenNames());
	    Attribute isVerified = new BasicAttribute("isVerified", Boolean.FALSE.toString().toUpperCase());

	    // Specify the DN we're adding
	    // TODO: do we create the principal, or is it a given?
	    Principal principal = p.getPrincipal();
	    String dn = principal.getValue();
	   
	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        orig.put(cn);
	        orig.put(sn);
	        //orig.put(givenNames);
	        orig.put(isVerified);
	        // Add the entry
	        ctx.createSubcontext(dn, orig);
	        log.debug( "Added entry " + dn);
	    } catch (NameAlreadyBoundException e) {
	        /* If entry exists already, fine.  Ignore this error. */
	    	log.warn("Entry " + dn + " already exists, no need to add", e);
	        //return false;
	    } catch (NamingException e) {
	    	log.error("Problem adding entry: " + dn, e);
	        return null;
	    }
		return principal;
	}
	
	private DirContext getContext() throws NamingException {
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

	public boolean removePrincipal(Principal p) {
		try {
			DirContext ctx = getContext();
			ctx.destroySubcontext(p.getValue());

	    } catch (NamingException e) {
	    	log.error("Error removing entry: " + p.getValue(), e);
	        return false;
	    }
	    return true;
	}
	
	// check the attribute for a given principal
	public boolean checkAttribute(Principal principal, String attributeName, String attributeValue) {
		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
		    ctls.setReturningAttributes(new String[0]);  // do not return any attributes
		    
		    String searchCriteria = attributeName + "=" + attributeValue;
		    
	        NamingEnumeration results = 
	            ctx.search(principal.getValue(), searchCriteria, ctls);
	        return (results != null && results.hasMoreElements());
	    } catch (NamingException e) {
	    	log.error("Problem checking attribute: " + attributeName, e);
	    }
	    return false;
		
	}
	
	private String parseAttribute(String original, String attribute) {
		String result = original;
		result = result.substring(result.indexOf( attribute + "="), result.indexOf(","));
		result = result.substring(result.indexOf("=") + 1) ;
		return result;
	}
	
	public static void main(String[] args) {
		try {
			
			Principal p = new Principal();
			p.setValue("cn=test1,dc=dataone,dc=org");
		
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.removePrincipal(p);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

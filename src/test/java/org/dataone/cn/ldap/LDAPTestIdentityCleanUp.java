/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.dataone.cn.ldap;

import javax.naming.InvalidNameException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Subject;

/**
 * Test Public and Protected members of the LDAPService class
 * 
 * @author waltz
 */
public class LDAPTestIdentityCleanUp extends LDAPService {
    public static Log log = LogFactory.getLog(LDAPTestIdentityCleanUp.class);
    private static DirContextProvider dirContextProvider = DirContextProvider.getInstance();
    private String subtree = Settings.getConfiguration().getString("identity.ldap.subtree", "dc=dataone");
    public LDAPTestIdentityCleanUp () {
         this.setBase(Settings.getConfiguration().getString("identity.ldap.base"));
    }
    
    public boolean removeEntry(String dn) throws ServiceFailure {
        boolean isRemoved = false;
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("-1000", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure( "-1000", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
             isRemoved = super.removeEntry(dirContext, dn);
		} finally {
			dirContextProvider.returnDirContext(dirContext);
		}
        return isRemoved;
    }
    public boolean removeSubject(Subject subject) throws ServiceFailure {
        return this.removeEntry(constructDn(subject.getValue()));
    }
    protected String constructDn(String subject) {
		String dn = subject;
		LdapName ldapName = null;
		try {
			ldapName = new LdapName(subject);
		} catch (InvalidNameException e) {
			log.warn("Subject not a valid DN: " + subject);
			//dn = "uid=" + subject.replaceAll("/", "\\2f") + "," + subtree + "," + this.getBase();
			dn = "uid=" + subject + "," + subtree + "," + this.getBase();
			log.info("Created DN from subject: " + dn);
			
		}
		
		return dn;
	}
    public boolean checkAttribute(String dn, String attributeName, String attributeValue) throws ServiceFailure {
        boolean isChecked = false;
        		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("-1000", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure( "-1000", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
             isChecked = super.checkAttribute(dirContext, dn, attributeName, attributeValue);
		} finally {
			dirContextProvider.returnDirContext(dirContext);
		}
        return isChecked;
    }
}

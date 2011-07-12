package org.dataone.service.cn;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.ldap.LDAPService;
import org.dataone.service.types.Identifier;
import org.dataone.service.types.Session;
import org.dataone.service.types.Subject;

/**
 * Class used for adding and managing reserved Identifiers
 * Identifiers are housed in LDAP and replicated across CNs
 * 
 * @author leinfelder
 *
 */
public class ReserveIdentifierService extends LDAPService {

	public static Log log = LogFactory.getLog(ReserveIdentifierService.class);
	
	/**
	 * Reserves the given Identifier for the Subject in the Session
	 * Checks ownership of the pid by the subject if it already exists
	 * TODO: update created date in cases where we are "re-reserving"?
	 * @param session
	 * @param pid
	 * @return
	 * @throws IdentifierNotUnique
	 */
	public boolean reserveIdentifier(Session session, Identifier pid) throws IdentifierNotUnique {
		Subject subject = session.getSubject();
		boolean ownedBySubject = false;

		// look up the identifier before attempting to add it
		String dn = lookupDN(pid);
		if (dn != null) {
			// check that it is ours since it exists
			ownedBySubject = checkAttribute(dn, "subject", subject.getValue());
			if (!ownedBySubject) {
				throw new IdentifierNotUnique("0000", 
						"Identifier (" + pid.getValue() + ") is reserved and not owned by subject, " + subject.getValue());
			}
			// TODO: update the date of the reservation?
		}
		
		// add an entry for the subject and pid
		boolean result = addEntry(subject, pid);
		
		return result;
	}
	
	/**
	 * Adds the entry to the LDAP store
	 * @param subject
	 * @param pid
	 * @return
	 * @throws IdentifierNotUnique
	 */
	private boolean addEntry(Subject subject, Identifier pid) throws IdentifierNotUnique {
		// Values we'll use in creating the entry
	    Attribute objClasses = new BasicAttribute("objectclass");
	    //objClasses.add("top");
	    objClasses.add("d1Reservation");
	    
	    // construct a DN from time
	    long time = System.currentTimeMillis();
	    String dn = "id=reservedIdentifier." + time;
	    
	    Attribute subjectAttribute = new BasicAttribute("subject", subject.getValue());
	    Attribute identifierAttribute = new BasicAttribute("identifier", pid.getValue());
	    Attribute createdAttribute = new BasicAttribute("created", new Date(time));
	    
	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);

	        orig.put(subjectAttribute);
	        orig.put(identifierAttribute);
	        orig.put(createdAttribute);

	        // Add the entry
	        ctx.createSubcontext(dn, orig);
	        log.debug( "Added entry " + dn);
	    } catch (NameAlreadyBoundException e) {
	        // If entry exists already, fine.  Ignore this error.
	    	String msg = "Entry " + dn + " already exists, no need to add";
	    	log.warn(msg, e);
	    	throw new IdentifierNotUnique("0000", msg);
	        //return false;
	    } catch (NamingException e) {
	    	log.error("Problem adding entry: " + dn, e);
	        return false;
	    }
		return true;
	}
	
	/**
	 * Searches for all reservedIdentifiers and removes those which are older than
	 * the numberOfDays specified
	 * @param numberOfDays
	 */
	private void expireEntries(int numberOfDays) {
		List<Identifier> identifiers = lookupReserverdIdentifiers();
		for (Identifier pid: identifiers) {
			// get the DN
			String dn = lookupDN(pid);
			// get the created attribute
			Date created = (Date) getAttributeValues(dn, "created").get(0);
			Calendar expires = Calendar.getInstance();
			expires.setTime(created);
			expires.add(Calendar.DATE, numberOfDays);
			Calendar today = Calendar.getInstance();
			if (expires.before(today)) {
				removeEntry(dn);
			}
		}
		
	}
	
	/**
	 * Find all the reserved Identifiers
	 * @return list of previously reserved Identifiers
	 */
	private List<Identifier> lookupReserverdIdentifiers() {
		
		List<Identifier> identifiers = new ArrayList<Identifier>();

		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		    
		    // search for all reservations
		    String searchCriteria = "(objectClass=d1Reservation)";
		    
	        NamingEnumeration<SearchResult> results = 
	            ctx.search(base, searchCriteria, ctls);
	        
	        while (results != null && results.hasMore()) {
	            SearchResult si = results.next();
	            String dn = si.getNameInNamespace();
	            log.debug("Search result found for: " + dn);
	            Attributes attributes = si.getAttributes();
	            NamingEnumeration<? extends Attribute> values = attributes.getAll();
	            while (values.hasMore()) {
	            	Attribute attribute = values.next();
					String attributeName = attribute.getID();
					if (attributeName.equalsIgnoreCase("identifier")) {
						String attributeValue = (String) attribute.get();
						Identifier pid = new Identifier();
						pid.setValue(attributeValue);
						identifiers.add(pid);
					}
	            }
	        }
		} catch (Exception e) {
			log.error("problem looking up identifiers", e);
		}
		
		return identifiers;
	}
	
	/**
	 * Find the DN for a given Identifier
	 * @param pid
	 * @return the DN in LDAP for the given pid
	 */
	private String lookupDN(Identifier pid) {
		
        String dn = null;

		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		    
		    // search for the given pid
		    String searchCriteria = "&((objectClass=d1Reservation)(identifier=" + pid.getValue() + "))";
		    
	        NamingEnumeration<SearchResult> results = 
	            ctx.search(base, searchCriteria, ctls);
	        
	        while (results != null && results.hasMore()) {
	            SearchResult si = results.next();
	            dn = si.getNameInNamespace();
	            log.debug("Search result found for: " + dn);
	            //return dn;
	            // or we could double check
	            Attributes attributes = si.getAttributes();
	            NamingEnumeration<? extends Attribute> values = attributes.getAll();
	            while (values.hasMore()) {
	            	Attribute attribute = values.next();
					String attributeName = attribute.getID();
					if (attributeName.equalsIgnoreCase("identifier")) {
						String attributeValue = (String) attribute.get();
						if (pid.getValue().equals(attributeValue)) {
							return dn;
						}
					}
	            }
	        }
		} catch (Exception e) {
			log.error("problem looking up DN for identifier: " + pid.getValue(), e);
		}
		return dn;
	}
	
}

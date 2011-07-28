package org.dataone.service.cn.impl.v1;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

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
import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.ldap.LDAPService;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;

/**
 * Class used for adding and managing reserved Identifiers
 * Identifiers are housed in LDAP and replicated across CNs
 *
 * @author leinfelder
 *
 */
public class ReserveIdentifierService extends LDAPService {

	public static Log log = LogFactory.getLog(ReserveIdentifierService.class);

	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

	private static Timer timer = null;

	public ReserveIdentifierService() {
		// we need to use a different base for the ids
		this.base = Settings.getConfiguration().getString("reserveIdentifier.ldap.base");
	}

	/**
	 * Reserves the given Identifier for the Subject in the Session
	 * Checks ownership of the pid by the subject if it already exists
	 * TODO: update created date in cases where we are "re-reserving"?
	 * @param session
	 * @param pid
	 * @return
	 * @throws IdentifierNotUnique
	 */
	public Identifier reserveIdentifier(Session session, Identifier pid, String scope, String format) throws IdentifierNotUnique {

		// TODO: construct pid from scope+format+calling some service

		Subject subject = session.getSubject();
		boolean ownedBySubject = false;

		// look up the identifier before attempting to add it
		String dn = lookupDN(pid);
		if (dn != null) {
			// check that it is ours since it exists
			ownedBySubject = checkAttribute(dn, "subject", subject.getValue());
			if (!ownedBySubject) {
				String msg = "Identifier (" + pid.getValue() + ") is reserved and not owned by subject, " + subject.getValue();
				log.warn(msg);
				throw new IdentifierNotUnique("0000", msg);
			}
			// TODO: update the date of the reservation?
		}

		// add an entry for the subject and pid
		boolean result = addEntry(subject, pid);

		return pid;
	}

	/**
	 *
	 * @param session
	 * @param pid
	 * @return
	 * @throws NotAuthorized
	 * @throws NotFound
	 */
	public boolean removeReservation(Session session, Identifier pid) throws NotAuthorized, NotFound {

		// check that we have the reservation
		if (hasReservation(session, pid)) {
			// look up the dn to remove it
			String dn = lookupDN(pid);
			if (dn != null) {
				boolean result = removeEntry(dn);
				return result;
			}
		}

		return false;
	}

	public boolean hasReservation(Session session, Identifier pid) throws NotAuthorized, NotFound {
		Subject subject = session.getSubject();
		boolean ownedBySubject = false;

		// look up the identifier
		String dn = lookupDN(pid);

		if (dn == null) {
			String msg = "No reservation found for pid: " + pid.getValue();
			throw new NotFound("0000", msg);
		} else {
			// check that it is ours since it exists
			ownedBySubject = checkAttribute(dn, "subject", subject.getValue());
			if (!ownedBySubject) {
				String msg = "Reserved Identifier (" + pid.getValue() + ") is not owned by subject, " + subject.getValue();
				throw new NotAuthorized("0000", msg);
			}
		}

		// we got this far, it is ours
		return true;
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
	    Calendar now = Calendar.getInstance();
	    String reservationId = "reservedIdentifier." + now.getTimeInMillis();
	    String dn = "reservationId=" + reservationId + "," + base;
	    String created = dateFormat.format(now.getTime());

	    Attribute idAttribute = new BasicAttribute("reservationId", reservationId);
	    Attribute subjectAttribute = new BasicAttribute("subject", subject.getValue());
	    Attribute identifierAttribute = new BasicAttribute("identifier", pid.getValue());
	    Attribute createdAttribute = new BasicAttribute("created", created);

	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        orig.put(idAttribute);
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
	 * @throws NamingException
	 */
	public void expireEntries(int numberOfDays) throws NamingException {
		List<Identifier> identifiers = lookupReservedIdentifiers();
		for (Identifier pid: identifiers) {
			// get the DN
			String dn = lookupDN(pid);
			// get the created attribute
			String createdObj = (String) getAttributeValues(dn, "created").get(0);
			//Date created = DatatypeConverter.parseDateTime(createdObj).getTime();
			Date created = null;
			try {
				created = dateFormat.parse(createdObj);
			} catch (ParseException e) {
				log.error("(skipping) Could not parse created date for entry: " + dn, e);
				continue;
			}

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
	 * Initializes the timer to run expiration checking every hour
	 * for the given service. All previously scheduled tasks are cancelled
	 * in favor of the service given in the param
	 * @param service the service instance that will be used to expire the entries
	 */
	public static void schedule(final ReserveIdentifierService service) {
		// cancel any previous schedule in favor of the service param
		if (timer != null) {
			timer.cancel();
		}
		// make a new timer
		timer = new Timer(true);
		// schedule the invocation
		TimerTask task = new TimerTask() {
			@Override
			public void run() {
				// expire day-old entries
				try {
					service.expireEntries(1);
				} catch (NamingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		};
		// run expiration every hour
		long period = 1000 * 60 * 60 * 1;
		timer.scheduleAtFixedRate(task, Calendar.getInstance().getTime(), period);
	}

	/**
	 * Find all the reserved Identifiers
	 * @return list of previously reserved Identifiers
	 */
	private List<Identifier> lookupReservedIdentifiers() {

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
		    String searchCriteria = "(&(objectClass=d1Reservation)(identifier=" + pid.getValue() + "))";

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
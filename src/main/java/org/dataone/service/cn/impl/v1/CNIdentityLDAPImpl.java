package org.dataone.service.cn.impl.v1;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.configuration.Settings;
import org.dataone.service.util.Constants;
import org.dataone.service.cn.v1.CNIdentity;
import org.dataone.cn.ldap.LDAPService;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectList;


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
public class CNIdentityLDAPImpl extends LDAPService implements CNIdentity {

	public static Log log = LogFactory.getLog(CNIdentityLDAPImpl.class);


	public CNIdentityLDAPImpl() {
		// we need to use a different base for the ids
		this.setBase(Settings.getConfiguration().getString("identity.ldap.base"));
	}
        @Override
        public void setBase(String base) {
            this.base = base;
        }
	public Subject createGroup(Session session, Subject groupName) throws ServiceFailure,
			InvalidToken, NotAuthorized, NotFound, NotImplemented,
			InvalidRequest, IdentifierNotUnique {

		/* objectClass groupOfUniqueNames....
		 * MUST ( uniqueMember $ cn )
		 * MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
		 */
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("groupOfUniqueNames");
	    //objClasses.add("d1Group");
	    Attribute cn = new BasicAttribute("cn", parseAttribute(groupName.getValue(), "cn"));
	    // use the Subject who creates the group
	    Subject groupAdmin = session.getSubject();
	    Attribute owner = new BasicAttribute("owner", groupAdmin.getValue());
	    // 'uniqueMember' is required
	    Attribute uniqueMember = new BasicAttribute("uniqueMember", groupAdmin.getValue());

	    // the DN for the group
	    String dn = groupName.getValue();

	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        orig.put(cn);
	        orig.put(uniqueMember);
	        orig.put(owner);
	        ctx.createSubcontext(dn, orig);
	        log.debug( "Created group " + dn + ".");
	    } catch (NameAlreadyBoundException e) {
	        // If entry exists
	    	String msg = "Group " + dn + " already exists";
	    	log.warn(msg);
	    	throw new IdentifierNotUnique("2400", msg);
	        //return false;
	    } catch (NamingException e) {
	    	throw new ServiceFailure("2490", "Could not create group: " + e.getMessage());
	    }

		return groupName;
	}

	@Override
    public boolean addGroupMembers(Session session, Subject groupName, SubjectList members)
    	throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

    	try {

	        // check that they have admin rights for group
	        Subject user = session.getSubject();
	        boolean canEdit = this.checkAttribute(groupName.getValue(), "owner", user.getValue());
	        if (!canEdit) {
	        	throw new NotAuthorized(null, "Subject not in owner list: " + user.getValue());
	        }

	        // context
	        DirContext ctx = getContext();

	        // collect all the subjects from groups and people
	        List<Subject> subjects = new ArrayList<Subject>();
	        for (Group group: members.getGroupList()) {
	        	subjects.add(group.getSubject());
	        }
	        for (Person person: members.getPersonList()) {
	        	subjects.add(person.getSubject());
	        }
	        for (Subject subject: subjects) {
		        // check that they are not already a member
	        	boolean isMember = this.checkAttribute(groupName.getValue(), "uniqueMember", subject.getValue());
	        	if (isMember) {
			        log.warn("Already a member: " + subject.getValue() + " of group: " + groupName.getValue() );
	        		continue;
	        	}
		        // add them as a member
		        ModificationItem[] mods = new ModificationItem[1];
		        Attribute mod0 = new BasicAttribute("uniqueMember", subject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(groupName.getValue(), mods);
		        log.debug("Added member: " + subject.getValue() + " to group: " + groupName.getValue() );
	        }
	    } catch (Exception e) {
	        throw new ServiceFailure("2590", e.getMessage());
	    }

    	return true;

    }

	@Override
    public boolean removeGroupMembers(Session session, Subject groupName, SubjectList members)
		throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

		try {

	        // check that they have admin rights for group
	        Subject user = session.getSubject();
	        boolean canEdit = this.checkAttribute(groupName.getValue(), "owner", user.getValue());
	        if (!canEdit) {
	        	throw new NotAuthorized(null, "Subject not in owner list: " + user.getValue());
	        }

	        // context
	        DirContext ctx = getContext();

	        //collect all the subjects from groups and people
	        List<Subject> subjects = new ArrayList<Subject>();
	        for (Group group: members.getGroupList()) {
	        	subjects.add(group.getSubject());
	        }
	        for (Person person: members.getPersonList()) {
	        	subjects.add(person.getSubject());
	        }
	        for (Subject subject: subjects) {
		        // remove them as a member
		        ModificationItem[] mods = new ModificationItem[1];
		        Attribute mod0 = new BasicAttribute("uniqueMember", subject.getValue());
		        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(groupName.getValue(), mods);
		        log.debug("Removed member: " + subject.getValue() + " from group: " + groupName.getValue() );
	        }
	    } catch (Exception e) {
	        throw new ServiceFailure("2690", e.getMessage());
	    }

		return true;

	}

    @Override
	public boolean mapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

	        // get the context
	        DirContext ctx = getContext();

	        // check if primary is confirming secondary
	        boolean confirmationRequest =
	        	checkAttribute(primarySubject.getValue(), "equivalentIdentityRequest", secondarySubject.getValue());

	        ModificationItem[] mods = null;
	        Attribute mod0 = null;
	        if (confirmationRequest) {
		        log.warn("Request already issued for: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
		        return false;
	        } else {
	        	// mark secondary as having the equivalentIdentityRequest
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentityRequest", primarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentityRequest on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
	        }

		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not map identity: " + e.getMessage());
	    }

		return true;
	}

	@Override
	public boolean confirmMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

		    // get the context
		    DirContext ctx = getContext();

		    // check if primary is confirming secondary
		    boolean confirmationRequest =
		    	checkAttribute(primarySubject.getValue(), "equivalentIdentityRequest", secondarySubject.getValue());

		    ModificationItem[] mods = null;
		    Attribute mod0 = null;
		    if (confirmationRequest) {
		        // update attribute on primarySubject
		        mods = new ModificationItem[2];
		        mod0 = new BasicAttribute("equivalentIdentity", secondarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // remove the request from primary since it is confirmed now
		        Attribute mod1 = new BasicAttribute("equivalentIdentityRequest", secondarySubject.getValue());
		        mods[1] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod1);
		        // make the change
		        ctx.modifyAttributes(primarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentity: " + primarySubject.getValue() + " = " + secondarySubject.getValue());

		        // update attribute on secondarySubject
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", primarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondarySubject.getValue(), mods);
		        log.debug("Successfully set reciprocal equivalentIdentity: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
		    } else {
		    	// no request to confirm
		        log.error("There is no identity mapping request to confim on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
		        return false;
		    }

		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not confirm identity mapping: " + e.getMessage());
		}

		return true;
	}

	@Override
	public Subject updateAccount(Session session, Person p) throws ServiceFailure,
		IdentifierNotUnique, InvalidCredentials, NotImplemented, InvalidRequest {

		Subject subject = p.getSubject();

		try {
			// the DN
			String dn = subject.getValue();

			// either it's in the dn, or we should construct it
		    String commonName = parseAttribute(dn, "cn");
		    if (commonName == null) {
			    if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
			    	commonName += p.getGivenName(0) + " ";
			    }
			    commonName += p.getFamilyName();
		    }
		    Attribute cn = new BasicAttribute("cn", commonName);
		    Attribute sn = new BasicAttribute("sn", p.getFamilyName());
		    Attribute givenNames = new BasicAttribute("givenName");
		    for (String givenName: p.getGivenNameList()) {
		    	givenNames.add(givenName);
		    }
		    Attribute mail = new BasicAttribute("mail");
		    for (String email: p.getEmailList()) {
		    	mail.add(email);
		    }
		    // Update isVerified attribute to false again
		    Attribute isVerified = new BasicAttribute("isVerified", Boolean.FALSE.toString().toUpperCase());

		    // get a handle to an Initial DirContext
		    DirContext ctx = getContext();

		    // construct the list of modifications to make
		    ModificationItem[] mods = new ModificationItem[5];
		    mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, cn);
		    mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, sn);
		    mods[2] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, givenNames);
		    mods[3] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mail);
		    mods[4] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, isVerified);

		    // make the change
		    ctx.modifyAttributes(dn, mods);
		    log.debug( "Updated entry: " + subject.getValue() );
		} catch (Exception e) {
		    throw new ServiceFailure("4530", "Could not update account: " + e.getMessage());
		}

		return subject;
	}

	@Override
	public boolean verifyAccount(Session session, Subject subject) throws ServiceFailure,
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
	        ctx.modifyAttributes(subject.getValue(), mods);
	        log.debug( "Verified subject: " + subject.getValue() );
	    } catch (NamingException e) {
	        throw new ServiceFailure("4540", "Could not verify account: " + e.getMessage());
	    }

		return true;
	}

	@Override
	public Subject registerAccount(Session session, Person p) throws ServiceFailure, IdentifierNotUnique, InvalidCredentials,
    NotImplemented, InvalidRequest {
	    // Values we'll use in creating the entry
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("person");
	    objClasses.add("organizationalPerson");
	    objClasses.add("inetOrgPerson");
	    objClasses.add("d1Principal");

	    // get the DN
	    Subject subject = p.getSubject();
	    String dn = subject.getValue();

	    // construct the tree as needed
	    try {
			constructTree(dn);
		} catch (NamingException e) {
			e.printStackTrace();
	    	throw new ServiceFailure("4520", "Could not counstruct partial tree: " + e.getMessage());
		}

	    // either it's in the dn, or we should construct it
	    String commonName = parseAttribute(dn, "cn");
	    if (commonName == null) {
		    if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
		    	commonName += p.getGivenName(0) + " ";
		    }
		    commonName += p.getFamilyName();
	    }

	    Attribute cn = new BasicAttribute("cn", commonName);
	    Attribute sn = new BasicAttribute("sn", p.getFamilyName());
	    Attribute givenNames = new BasicAttribute("givenName");
	    for (String givenName: p.getGivenNameList()) {
	    	givenNames.add(givenName);
	    }
	    Attribute mail = new BasicAttribute("mail");
	    for (String email: p.getEmailList()) {
	    	mail.add(email);
	    }
	    Attribute isVerified = new BasicAttribute("isVerified", Boolean.FALSE.toString().toUpperCase());

	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        if (cn.getAll().hasMore()) {
	        	orig.put(cn);
	        }
	        if (sn.getAll().hasMore()) {
	        	orig.put(sn);
	        }
	        if (givenNames.getAll().hasMore()) {
	        	orig.put(givenNames);
	        }
	        if (mail.getAll().hasMore()) {
		        orig.put(mail);
	        }
	        orig.put(isVerified);
	        // Add the entry
	        ctx.createSubcontext(dn, orig);
	        log.debug( "Added entry " + dn);
	    } catch (NameAlreadyBoundException e) {
	    	String msg = "Entry " + dn + " already exists";
	        // If entry exists already
	    	log.warn(msg, e);
	        throw new IdentifierNotUnique("4521", msg);
	    } catch (NamingException e) {
	    	throw new ServiceFailure("4520", "Could not register account: " + e.getMessage());
	    }
		return subject;
	}

	@Override
	public SubjectList getSubjectInfo(Session session, Subject subject)
    	throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented {

		SubjectList pList = new SubjectList();
	    String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			pList = processAttributes(dn, attributes);
			log.debug("Retrieved SubjectList for: " + dn);
		} catch (Exception e) {
			String msg = "Problem looking up entry: " + dn + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("4561", msg);
		}

		return pList;
	}

	// TODO: use query and start/count params
	@Override
	public SubjectList listSubjects(Session session, String query, Integer start,
	        Integer count) throws ServiceFailure, InvalidToken, NotAuthorized,
	        NotImplemented {

		SubjectList pList = new SubjectList();
		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		    // search for principals and groups
		    String searchCriteria = "(|(objectClass=d1Principal)(objectClass=groupOfUniqueNames))";

	        NamingEnumeration<SearchResult> results =
	            ctx.search(base, searchCriteria, ctls);

	        while (results != null && results.hasMore()) {
	            SearchResult si = results.next();
	            String dn = si.getNameInNamespace();
	            log.debug("Search result found for: " + dn);
	            Attributes attrs = si.getAttributes();
                SubjectList resultList = processAttributes(dn, attrs);
                if (resultList != null) {
                	// add groups
	                for (Group group: resultList.getGroupList()) {
		                pList.addGroup(group);
	                }
	                // add people
	                for (Person person: resultList.getPersonList()) {
		                pList.addPerson(person);
	                }
                }
	        }

	    } catch (Exception e) {
	    	String msg = "Problem listing entries at base: " + base + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("2290", msg);
	    }

	    return pList;
	}
	
    @Override
	public boolean isGroup(Session session, Subject subject) 
	throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
    	SubjectList subjectList = this.getSubjectInfo(session, subject);
    	// we have a group
    	if (subjectList.getGroupList() != null && subjectList.getGroupList().size() > 0) {
    		// we have no people
    		if (subjectList.getPersonList() == null || subjectList.getPersonList().size() == 0) {
    			return true;
    		}
    	}
    	
    	return false;
    	
    }
 
    @Override
    public boolean isPublic(Session session, Subject subject) 
    throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
    	return subject.getValue().equals(Constants.PUBLIC_SUBJECT);
    }

	private SubjectList processAttributes(String name, Attributes attributes) throws Exception {

		SubjectList pList = new SubjectList();


		if (attributes != null) {
			NamingEnumeration<String> objectClasses = (NamingEnumeration<String>) attributes.get("objectClass").getAll();
			boolean isGroup = true;
			while (objectClasses.hasMore()) {
				String objectClass = objectClasses.next();
				if (objectClass.equalsIgnoreCase("d1Principal")) {
					isGroup = false;
					break;
				}
			}

			// get all attributes for processing
			NamingEnumeration<? extends Attribute> values = attributes.getAll();
			// for handling multi-item attributes
			NamingEnumeration<String> items = null;

			// process as Group
			if (isGroup) {
				Group group = new Group();
				Subject subject = new Subject();
				subject.setValue(name);
				group.setSubject(subject);

				while (values.hasMore()) {
					Attribute attribute = values.next();
					String attributeName = attribute.getID();
					String attributeValue = null;

					if (attributeName.equalsIgnoreCase("cn")) {
						attributeValue = (String) attribute.get();
						group.setGroupName(attributeValue);
						log.debug("Found attribute: " + attributeName + "=" + attributeValue);
					}
					if (attributeName.equalsIgnoreCase("uniqueMember")) {
						items = (NamingEnumeration<String>) attribute.getAll();
						while (items.hasMore()) {
							attributeValue = items.next();
							Subject member = new Subject();
							member.setValue(attributeValue);
							group.addHasMember(member);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
						}
					}
				}
				pList.addGroup(group);

			} else {
				// process as a person
				Person person = new Person();
				Subject subject = new Subject();
				subject.setValue(name);
				person.setSubject(subject);

				while (values.hasMore()) {
					Attribute attribute = values.next();
					String attributeName = attribute.getID();
					String attributeValue = null;

					if (attributeName.equalsIgnoreCase("cn")) {
						attributeValue = (String) attribute.get();
						log.debug("Found attribute: " + attributeName + "=" + attributeValue);
					}
					if (attributeName.equalsIgnoreCase("sn")) {
						attributeValue = (String) attribute.get();
						person.setFamilyName(attributeValue);
						log.debug("Found attribute: " + attributeName + "=" + attributeValue);
					}
					if (attributeName.equalsIgnoreCase("mail")) {
						items = (NamingEnumeration<String>) attribute.getAll();
						while (items.hasMore()) {
							attributeValue = items.next();
							person.addEmail(attributeValue);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
						}
					}
					if (attributeName.equalsIgnoreCase("givenName")) {
						items = (NamingEnumeration<String>) attribute.getAll();
						while (items.hasMore()) {
							attributeValue = items.next();
							person.addGivenName(attributeValue);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
						}
					}
					if (attributeName.equalsIgnoreCase("equivalentIdentity")) {
						items = (NamingEnumeration<String>) attribute.getAll();
						while (items.hasMore()) {
							attributeValue = items.next();
							Subject equivalentIdentity = new Subject();
							equivalentIdentity.setValue(attributeValue);
							person.addEquivalentIdentity(equivalentIdentity);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
						}
					}
					// TODO: store in person, or only in group entry?
					if (attributeName.equalsIgnoreCase("memberOf")) {
						items = (NamingEnumeration<String>) attribute.getAll();
						while (items.hasMore()) {
							attributeValue = items.next();
							Subject group = new Subject();
							group.setValue(attributeValue);
							person.addIsMemberOf(group);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
						}
					}
				}
				// TODO: handle group membership here?

				pList.addPerson(person);
			}
		}

		return pList;
	}

	public boolean removeSubject(Subject p) {
		return super.removeEntry(p.getValue());
	}

	public static void main(String[] args) {
		try {

			Subject p = new Subject();
//			p.setValue("cn=testGroup,dc=cilogon,dc=org");
			p.setValue("cn=testGroup,dc=cilogon,dc=org");

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer("ldap://bespin.nceas.ucsb.edu:389");
			identityService.removeSubject(p);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

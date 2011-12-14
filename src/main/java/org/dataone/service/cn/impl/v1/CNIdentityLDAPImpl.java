package org.dataone.service.cn.impl.v1;

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
import org.dataone.client.D1Client;
import org.dataone.client.auth.CertificateManager;
import org.dataone.cn.ldap.LDAPService;
import org.dataone.configuration.Settings;
import org.dataone.service.cn.v1.CNIdentity;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v1.Node;
import org.dataone.service.types.v1.NodeType;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.types.v1.SubjectList;
import org.dataone.service.util.Constants;
import org.dataone.service.cn.impl.v1.NodeRegistryService;
import org.dataone.service.types.v1.NodeList;

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

        private NodeRegistryService nodeRegistryService = new NodeRegistryService();
	public CNIdentityLDAPImpl() {
		// we need to use a different base for the ids
		this.setBase(Settings.getConfiguration().getString("identity.ldap.base"));
	}
        @Override
        public void setBase(String base) {
            this.base = base;
        }
	public Subject createGroup(Session session, Subject groupName) throws ServiceFailure,
			InvalidToken, NotAuthorized, NotImplemented,
			IdentifierNotUnique {

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

    		// will throw NotAuthorized if not true
			boolean canEdit = canEditGroup(session, groupName);

	        // context
	        DirContext ctx = getContext();

	        // collect all the subjects from groups and people
	        List<Subject> subjects = members.getSubjectList();
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
	    } catch (NamingException e) {
	        throw new ServiceFailure("2590", "Could not add group members: " + e.getMessage());
	    }

    	return true;

    }

	@Override
    public boolean removeGroupMembers(Session session, Subject groupName, SubjectList members)
		throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

		try {
			
			// will throw NotAuthorized if not true
			boolean canEdit = canEditGroup(session, groupName);

	        // context
	        DirContext ctx = getContext();

	        //collect all the subjects from groups and people
	        List<Subject> subjects = members.getSubjectList();
	        for (Subject subject: subjects) {
		        // remove them as a member
		        ModificationItem[] mods = new ModificationItem[1];
		        Attribute mod0 = new BasicAttribute("uniqueMember", subject.getValue());
		        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(groupName.getValue(), mods);
		        log.debug("Removed member: " + subject.getValue() + " from group: " + groupName.getValue() );
	        }
	    } catch (NamingException e) {
	        throw new ServiceFailure("2690", "Could not remove group members: " + e.getMessage());
	    }

		return true;

	}
	
	private boolean canEditGroup(Session session, Subject groupName) throws NamingException, NotAuthorized {
		// check that they have admin rights for group
        boolean canEdit = false;
        Subject user = session.getSubject();
        String userDN = CertificateManager.getInstance().standardizeDN(user.getValue());
        List<Object> owners = this.getAttributeValues(groupName.getValue(), "owner");
        for (Object ownerObj: owners) {
        	String owner = (String) ownerObj;
        	owner = CertificateManager.getInstance().standardizeDN(owner);
        	if (userDN.equals(owner)) {
        		canEdit = true;
        		break;
        	}
        }
        
        if (!canEdit) {
        	throw new NotAuthorized("2560", "Subject not in owner list: " + userDN);
        }
        
        return canEdit;
	}

    @Override
	public boolean mapIdentity(Session session, Subject primarySubject, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

        int failureCount = 0;
        boolean isAllowed = false;
        Subject sessionSubject = null;

        // TODO: check for admin user (MN?) in the Session object
        isAllowed = true;
//        sessionSubject = session.getSubject();
//        for (Node node: D1Client.getCN().listNodes().getNodeList()) {
//        	for (Subject nodeSubject: node.getSubjectList()) {
//        		if (nodeSubject.getValue().equals(sessionSubject.getValue())) {
//        			isAllowed = true;
//        			break;
//        		}
//        	}
//        	// get out of the loop if we already now we can
//        	if (isAllowed) {
//        		break;
//        	}
//        }
//        if (!isAllowed) {
//        	throw new NotAuthorized("2360", sessionSubject.getValue() + " is not allowed to map identities");
//        }
        
        // check for pre-existing mapping
        boolean mappingExists =
	    	checkAttribute(primarySubject.getValue(), "equivalentIdentity", secondarySubject.getValue());
        if (mappingExists) {
	    	throw new InvalidRequest("", "Account mapping already exists");
        }
        
		try {
			
	        // get the context
	        DirContext ctx = getContext();
	        ModificationItem[] mods = null;
	        Attribute mod0 = null;
	        
	        // mark primary as having the equivalentIdentity
	        try {
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", secondarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(primarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentity on: " + primarySubject.getValue() + " for " + secondarySubject.getValue());
	        } catch (Exception e) {
				// one failure is OK, two is not
		        log.warn("Could not set equivalentIdentity on: " + primarySubject.getValue() + " for " + secondarySubject.getValue(), e);
		        failureCount++;
			}
	        
        	// mark secondary as having the equivalentIdentity
	        try {
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", primarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentity on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
	        } catch (Exception e) {
				// one failure is OK, two is not
		        log.warn("Could not set equivalentIdentity on: " + secondarySubject.getValue() + " for " + primarySubject.getValue(), e);
		        failureCount++;
			}
	        
	        
		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not map identity: " + e.getMessage());
	    }
		
		// one account need not exist and this should still succeed
		if (failureCount > 1) {
	    	throw new ServiceFailure("2390", "Could not map identity, neither account could be edited.");
		}
		
		return true;
	}
    
	@Override
	public boolean requestMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

	        // get the context
	        DirContext ctx = getContext();

	        // check if request already exists
	        boolean confirmationRequested =
	        	checkAttribute(primarySubject.getValue(), "equivalentIdentityRequest", secondarySubject.getValue());
	        
	        if (confirmationRequested) {
		        throw new InvalidRequest("", "Request already issued for: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
	        } else {
	        	ModificationItem[] mods = null;
		        Attribute mod0 = null;
	        	// mark secondary as having the equivalentIdentityRequest
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentityRequest", primarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentityRequest on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
	        }

		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not request map identity: " + e.getMessage());
	    }

		return true;
	}

	@Override
	public boolean confirmMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {

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
		        throw new InvalidRequest("", "There is no identity mapping request to confim on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
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
	public SubjectInfo getSubjectInfo(Session session, Subject subject)
    	throws ServiceFailure, NotAuthorized, NotImplemented {
		return getSubjectInfo(session, subject, true);
	}
	
	private SubjectInfo getSubjectInfo(Session session, Subject subject, boolean recurse)
    	throws ServiceFailure, NotAuthorized, NotImplemented {

		// check redaction policy
		boolean redact = isUnredacted(session);
		
		SubjectInfo subjectInfo = new SubjectInfo();
	    String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			subjectInfo = processAttributes(dn, attributes, recurse, false, redact);
			log.debug("Retrieved SubjectList for: " + dn);
		} catch (Exception e) {
			String msg = "Problem looking up entry: " + dn + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("4561", msg);
		}

		return subjectInfo;
	}

	// TODO: use query and start/count params
	@Override
	public SubjectInfo listSubjects(Session session, String query, String status, Integer start,
	        Integer count) throws ServiceFailure, InvalidToken, NotAuthorized,
	        NotImplemented {

		// check redaction policy
		boolean redact = isUnredacted(session);
		
		SubjectInfo pList = new SubjectInfo();
		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		    // search for all principals and groups
		    String searchCriteria = "(|(objectClass=d1Principal)(objectClass=groupOfUniqueNames))";
		    
		    // constrain to match query string if we have it
		    if (query != null && query.length() > 0) {
		    	String queryCriteria = 
		    		"(|" +
	    				"(dn=*" + query + "*)" +
		    			"(cn=*" + query + "*)" +
		    			"(sn=*" + query + "*)" +
		    			"(givenName=*" + query + "*)" +
		    			"(mail=*" + query + "*)" +
		    		")";
		    	// combine the query with the object class restriction 
		    	searchCriteria = "(&" + queryCriteria + searchCriteria + ")";
		    }
		    // tack on the status filter
		    if (status != null) {
			    Boolean isVerified = new Boolean(status.equalsIgnoreCase("verified"));
		    	// verified is a boolean in ldap
		    	String statusCriteria = "(isVerified=" + isVerified.toString().toUpperCase() + ")";
		    	searchCriteria = "(&" + statusCriteria + searchCriteria + ")";
		    }

	        NamingEnumeration<SearchResult> results =
	            ctx.search(base, searchCriteria, ctls);

	        while (results != null && results.hasMore()) {
	            SearchResult si = results.next();
	            String dn = si.getNameInNamespace();
	            log.debug("Search result found for: " + dn);
	            Attributes attrs = si.getAttributes();
	            // DO NOT look up other details about matching Groups or Persons, nor include equivalentIdentity requests
	            SubjectInfo resultList = processAttributes(dn, attrs, false, false, redact);
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
	
//    @Override
//	public boolean isGroup(Session session, Subject subject) 
//	throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
//    	SubjectInfo subjectInfo = this.getSubjectInfo(session, subject);
//    	// we have a group
//    	if (subjectInfo.getGroupList() != null && subjectInfo.getGroupList().size() > 0) {
//    		// we have no people
//    		if (subjectInfo.getPersonList() == null || subjectInfo.getPersonList().size() == 0) {
//    			return true;
//    		}
//    	}
//    	
//    	return false;
//    	
//    }
// 
//    @Override
//    public boolean isPublic(Session session, Subject subject) 
//    throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
//    	return subject.getValue().equals(Constants.SUBJECT_PUBLIC);
//    }

	private SubjectInfo processAttributes(String name, Attributes attributes, boolean recurse, boolean equivalentIdentityRequestsOnly, boolean redact) throws Exception {

		SubjectInfo pList = new SubjectInfo();

		// convert to use the standardized string representation
		name = CertificateManager.getInstance().standardizeDN(name);

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
							// look up details for this Group member?
							if (recurse) {
								// only one level of recursion
								SubjectInfo groupInfo = this.getSubjectInfo(null, member, false);
								// has people as members?
								if (groupInfo.getPersonList() != null) {
									for (Person p: groupInfo.getPersonList()) {
										pList.addPerson(p);
									}
								}
								// has other groups as members?
								if (groupInfo.getGroupList() != null) {
									for (Group g: groupInfo.getGroupList()) {
										pList.addGroup(g);
									}
								}
							}
						}
					}
				}
				pList.getGroupList().add(0, group);

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
						// should email be redacted?
						if (!redact) {
							items = (NamingEnumeration<String>) attribute.getAll();
							while (items.hasMore()) {
								attributeValue = items.next();
								person.addEmail(attributeValue);
								log.debug("Found attribute: " + attributeName + "=" + attributeValue);
							}
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
					if (attributeName.equalsIgnoreCase("isVerified")) {
						attributeValue = (String) attribute.get();
						person.setVerified(Boolean.parseBoolean(attributeValue));
						log.debug("Found attribute: " + attributeName + "=" + attributeValue);
					}
					// do we care about the requests or just the confirmed ones?
					if (equivalentIdentityRequestsOnly) {
						if (attributeName.equalsIgnoreCase("equivalentIdentityRequest")) {
							items = (NamingEnumeration<String>) attribute.getAll();
							while (items.hasMore()) {
								attributeValue = items.next();
								Subject equivalentIdentityRequest = new Subject();
								equivalentIdentityRequest.setValue(attributeValue);
								log.debug("Found attribute: " + attributeName + "=" + attributeValue);
								// add this identity to the subject list?
								if (recurse) {
									// catch the NotFound in case we only have the subject's DN
									try {
										// only one level of recursion
										SubjectInfo equivalentIdentityRequestInfo = this.getSubjectInfo(null, equivalentIdentityRequest, false);
										if (equivalentIdentityRequestInfo.getPersonList() != null) {
											for (Person p: equivalentIdentityRequestInfo.getPersonList()) {
												pList.addPerson(p);
											}
										}
									} catch (ServiceFailure e) {
										// ignore NotFound
										log.warn("No account found for equivalentIdentityRequest entry: " + equivalentIdentityRequest.getValue(), e);
										// still add this placeholder
										Person placeholderPerson = new Person();
										placeholderPerson.setSubject(equivalentIdentityRequest);
										placeholderPerson.addEmail("NA");
										placeholderPerson.addGivenName("NA");
										placeholderPerson.setFamilyName("NA");
										pList.addPerson(placeholderPerson);
									}
								}
							}
						}
					} else {
						if (attributeName.equalsIgnoreCase("equivalentIdentity")) {
							items = (NamingEnumeration<String>) attribute.getAll();
							while (items.hasMore()) {
								attributeValue = items.next();
								Subject equivalentIdentity = new Subject();
								equivalentIdentity.setValue(attributeValue);
								person.addEquivalentIdentity(equivalentIdentity);
								log.debug("Found attribute: " + attributeName + "=" + attributeValue);
								// add this identity to the subject list
								if (recurse) {
									// allow case where the identity is not found
									try {
										// only one level of recursion
										SubjectInfo equivalentIdentityInfo = this.getSubjectInfo(null, equivalentIdentity, false);
										if (equivalentIdentityInfo.getPersonList() != null) {
											for (Person p: equivalentIdentityInfo.getPersonList()) {
												pList.addPerson(p);
											}
										}
									} catch (ServiceFailure e) {
										// ignore NotFound
										log.warn("No account found for equivalentIdentity entry: " + equivalentIdentity.getValue(), e);
										// still add this placeholder
										Person placeholderPerson = new Person();
										placeholderPerson.setSubject(equivalentIdentity);
										placeholderPerson.addEmail("NA");
										placeholderPerson.addGivenName("NA");
										placeholderPerson.setFamilyName("NA");
										pList.addPerson(placeholderPerson);
									}
								}
							}
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
							// look up details for this Group?
							if (recurse) {
								// only one level of recursion
								SubjectInfo groupInfo = this.getSubjectInfo(null, group, false);
								if (groupInfo.getGroupList() != null) {
									for (Group g: groupInfo.getGroupList()) {
										pList.addGroup(g);
									}
								}
								// NOTE: this does not make sense to include other members
								// has members?
	//							if (groupInfo.getPersonList() != null) {
	//								for (Person p: groupInfo.getPersonList()) {
	//									pList.addPerson(p);
	//								}
	//							}
							}
						}
					}
				}
				// add as the first one in the list
				pList.getPersonList().add(0, person);
			}
		}

		return pList;
	}

	public boolean removeSubject(Subject p) {
		return super.removeEntry(p.getValue());
	}
	
	@Override
	public boolean denyMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {
		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

	        // get the context
	        DirContext ctx = getContext();

	        // check if primary has the request from secondary
	        boolean confirmationRequest =
	        	checkAttribute(primarySubject.getValue(), "equivalentIdentityRequest", secondarySubject.getValue());

	        ModificationItem[] mods = null;
	        Attribute mod0 = null;
	        if (!confirmationRequest) {
		        throw new InvalidRequest("", "Identity mapping request has not been issued for: " + primarySubject.getValue() + " = " + secondarySubject.getValue());
	        } else {
	        	// remove the request
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentityRequest", secondarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(primarySubject.getValue(), mods);
		        log.debug("Successfully removed equivalentIdentityRequest on: " + primarySubject.getValue() + " for " + secondarySubject.getValue());
	        }

		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not deny the identity mapping: " + e.getMessage());
	    }

		return true;
	}
	
	@Override
	public SubjectInfo getPendingMapIdentity(Session session, Subject subject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {
		
		// check redaction policy
		boolean redact = isUnredacted(session);
		
		SubjectInfo subjectInfo = new SubjectInfo();
	    String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			// include the equivalent identity requests only
			subjectInfo = processAttributes(dn, attributes, true, true, redact);
			log.debug("Retrieved SubjectList for: " + dn);
		} catch (Exception e) {
			String msg = "Problem looking up entry: " + dn + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("4561", msg);
		}

		return subjectInfo;
		
	}
	
	@Override
	public boolean removeMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {
		
		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

		    // get the context
		    DirContext ctx = getContext();

		    // check if primary has secondary equivalence
		    boolean mappingExists =
		    	checkAttribute(primarySubject.getValue(), "equivalentIdentity", secondarySubject.getValue());
		    boolean reciprocolMappingExists =
		    	checkAttribute(secondarySubject.getValue(), "equivalentIdentity", primarySubject.getValue());

		    ModificationItem[] mods = null;
		    Attribute mod0 = null;
		    // allow removal of one-way mapping in cases where identity is not registered in D1
		    if (mappingExists || reciprocolMappingExists) {
		    	
		        // remove attribute on primarySubject
		    	if (mappingExists) {
			        mods = new ModificationItem[1];
			        mod0 = new BasicAttribute("equivalentIdentity", secondarySubject.getValue());
			        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
			        // make the change
			        ctx.modifyAttributes(primarySubject.getValue(), mods);
			        log.debug("Successfully removed equivalentIdentity: " + primarySubject.getValue() + " = " + secondarySubject.getValue());
		    	}
		    	
		        // remove attribute on secondarySubject
		    	if (reciprocolMappingExists) {
			        mods = new ModificationItem[1];
			        mod0 = new BasicAttribute("equivalentIdentity", primarySubject.getValue());
			        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
			        // make the change
			        ctx.modifyAttributes(secondarySubject.getValue(), mods);
			        log.debug("Successfully removed reciprocal equivalentIdentity: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
		    	}
		    	
		    } else {
		    	// neither mapping is valid
		        throw new InvalidRequest("", "There is no identity mapping between: " + primarySubject.getValue() + " and " + secondarySubject.getValue());
		    }

		} catch (Exception e) {
	    	throw new ServiceFailure("2390", "Could not remove identity mapping: " + e.getMessage());
		}

		return true;
	}
	
	private boolean isUnredacted(Session session) throws NotImplemented, ServiceFailure {
		
		// CN should see unredacted list
		if (session != null) {
            // first check locally
			NodeList nodeList = null;
			try {
				nodeList = nodeRegistryService.listNodes();
			} catch (Exception e) {
				// probably don't have it set up locally, defer to CN via client
				log.warn("Using D1Client to look up nodeList from CN");
				nodeList = D1Client.getCN().listNodes();
			}
			for (Node node: nodeList.getNodeList()) {
				if (node.getType().equals(NodeType.CN)) {
					for (Subject subject: node.getSubjectList()) {
						if (subject.getValue().equals(session.getSubject().getValue())) {
							return true;
						}
					}
				}
			}
		} 
		return false;
	}

	public static void main(String[] args) {
		try {

			Subject p = new Subject();
//			p.setValue("cn=testGroup,dc=cilogon,dc=org");
			p.setValue("CN=Benjamin Leinfelder A458,O=University of Chicago,C=US,DC=cilogon,DC=org");

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer("ldap://cn-dev.dataone.org:389");
			//identityService.removeSubject(p);
			SubjectInfo si = identityService.getSubjectInfo(null, p);
			String subjectDn = si.getPerson(0).getSubject().getValue();
			System.out.println(subjectDn);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

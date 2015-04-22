/**
 * This work was created by participants in the DataONE project, and is
 * jointly copyrighted by participating institutions in DataONE. For 
 * more information on DataONE, see our web site at http://dataone.org.
 *
 *   Copyright ${year}
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 * 
 * $Id$
 */

package org.dataone.service.cn.impl.v2;

import java.util.Collection;
import java.util.List;

import javax.naming.NameAlreadyBoundException;
import javax.naming.NameNotFoundException;
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
import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.v2.itk.D1Client;
import org.dataone.client.auth.CertificateManager;
import org.dataone.cn.ldap.LDAPService;
import org.dataone.configuration.Settings;
import org.dataone.service.cn.v2.CNIdentity;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v2.Node;
import org.dataone.service.types.v1.NodeType;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.cn.impl.v2.NodeRegistryService;
import org.dataone.service.types.v2.NodeList;
import org.dataone.service.types.v1.util.AuthUtils;
import org.dataone.service.types.v2.util.ServiceMethodRestrictionUtil;

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
        
    @Override    
	public Subject createGroup(Session session, Group group) throws ServiceFailure,
			InvalidToken, NotAuthorized, NotImplemented,
			IdentifierNotUnique, InvalidRequest {

    	Subject groupName = group.getSubject();
	    Subject groupAdmin = session.getSubject();

		/* objectClass groupOfUniqueNames....
		 * MUST ( uniqueMember $ cn )
		 * MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
		 */
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("groupOfUniqueNames");
	    //objClasses.add("d1Group");
	    Attribute cn = new BasicAttribute("cn", parseAttribute(groupName.getValue(), "cn"));
	    
	    // the creator is 'owner' by default
	    Attribute owners = new BasicAttribute("owner");
	    owners.add(groupAdmin.getValue());
	    // add all other rightsHolders as 'owner' too
	    if (group.getRightsHolderList() != null) {
		    for (Subject rightsHolder: group.getRightsHolderList()) {
		    	owners.add(rightsHolder.getValue());
		    }
	    }
	    
	    // 'uniqueMember' is required, so always add the creator
	    Attribute uniqueMembers = new BasicAttribute("uniqueMember");
	    uniqueMembers.add(groupAdmin.getValue());
	    
	    // add all other members as 'uniqueMembers'
	    if (group.getHasMemberList() != null) {
		    for (Subject member: group.getHasMemberList()) {
		    	// check if they are trying to add a group as a member
		    	boolean memberIsGroup = false;
		    	try {
		    		List<Object> values = this.getAttributeValues(member.getValue(), "uniqueMember");
		    		if (!values.isEmpty()) {
		    			memberIsGroup = true;
		    		}
		    	} catch (Exception e) {
					log.warn("Could not check whether member subject is a group: " + e.getMessage());
				}

		    	// throw error, rather than just continuing without this member
	    		if (memberIsGroup) {
	    			throw new InvalidRequest("0000", "Group member: " + member.getValue() + " cannot be another Group");
	    		} else {
		    		uniqueMembers.add(member.getValue());
		    	}
		    }
	    }

	    // the DN for the group
	    String dn = groupName.getValue();

	    try {
		    DirContext ctx = getContext();
	        Attributes orig = new BasicAttributes();
	        orig.put(objClasses);
	        orig.put(cn);
	        orig.put(uniqueMembers);
	        orig.put(owners);
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
    public boolean updateGroup(Session session, Group group)
    	throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

		Subject groupSubject = group.getSubject();
		
		// back up the original before updating
		SubjectInfo originalGroup = this.getSubjectInfo(session, groupSubject);
		
		try {
    		
    		// will throw NotAuthorized if not true		
			boolean canEdit = canEditGroup(session, groupSubject);
						
			// remove the group
			this.removeSubject(groupSubject);
			
		} catch (NamingException e) {
			ServiceFailure sf = new ServiceFailure("2490", "Could not update group: " + e.getMessage());
			sf.initCause(e);
			throw sf;
		}
		
		// recreate the group using the provided input
		Exception createException = null;
		try {
			this.createGroup(session, group);
		} catch (IdentifierNotUnique e) {
			createException = e;
		} catch (InvalidRequest e) {
			createException = e;
		}
		
		// recreate what we deleted if there was an error
		if (createException != null) {
			try {
				this.createGroup(session, originalGroup.getGroup(0));
			} catch (IdentifierNotUnique e) {
				ServiceFailure sf = new ServiceFailure("2490", "Could not recreate original group after update failed: " + e.getMessage());
				sf.initCause(e);
				throw sf;
			}
			// report the original error accurately
			if (createException instanceof InvalidRequest) {
				throw (InvalidRequest) createException;
			} else {
				ServiceFailure sf = new ServiceFailure("2490", "Could not update group: " + createException.getMessage());
				sf.initCause(createException);
				throw sf;
			}
		}	

    	return true;

    }
	
	private boolean canEditGroup(Session session, Subject groupName) throws NamingException, NotAuthorized {
		// check that they have admin rights for group
        boolean canEdit = false;
        // collect all equivalent IDs for this session
        Collection<Subject> sessionSubjects = AuthUtils.authorizedClientSubjects(session);
 
        // find the admin list of the group
        List<Object> owners = this.getAttributeValues(groupName.getValue(), "owner");
 
        // do any of our subjects match the owners?
        ownerSearch:
        for (Subject user: sessionSubjects) {
	        String userDN = user.getValue();
        	try {
    	        userDN = CertificateManager.getInstance().standardizeDN(userDN);
        	} catch (IllegalArgumentException iae) {
        		// ignore, "public", "verified" etc...
        	}
	        for (Object ownerObj: owners) {
	        	String owner = (String) ownerObj;
	        	owner = CertificateManager.getInstance().standardizeDN(owner);
	        	if (userDN.equals(owner)) {
	        		canEdit = true;
	        		break ownerSearch;
	        	}
	        }
	    }
        
        // throw exception if not authorized
        if (!canEdit) {
        	throw new NotAuthorized("2560", "Subject not in owner list for group");
        }
        
        return canEdit;
	}
	
	private boolean canEditPerson(Session session, Subject personSubject) throws NotAuthorized {
		// check that they have rights for person
        boolean canEdit = false;
        // collect all equivalent IDs for this session
        Collection<Subject> sessionSubjects = null;
        sessionSubjects = AuthUtils.authorizedClientSubjects(session);
        
        // do any of our subjects match the subject being edited?
        for (Subject user: sessionSubjects) {
	        String sessionDN = user.getValue();
        	try {
    	        sessionDN = CertificateManager.getInstance().standardizeDN(sessionDN);
        	} catch (IllegalArgumentException iae) {
        		// ignore, "public", "verified" etc...
        	}
        	String listedDN = personSubject.getValue();
        	listedDN = CertificateManager.getInstance().standardizeDN(listedDN);

        	if (sessionDN.equals(listedDN)) {
        		canEdit = true;
        		break;
        	}
	    }
        
        // throw exception if not authorized
        if (!canEdit) {
        	throw new NotAuthorized("4534", "Subject not allowed to edit subject");
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

        // checks if we are allowed to call this method -- should be very restricted
        List<Node> nodeList = null;
        try {
        	nodeList = nodeRegistryService.listNodes().getNodeList();
        } catch (Exception e) {
                // probably don't have it set up locally, defer to CN via client
                // XXX, it should be set up locally, this code will never
                // execute outside the context of a running local instance of a CN
                //  a client connection from a CN to itself should not be considered
                // an option.  This  piece of code  convinces me that
                // d1_identity_manager is no longer a viable independent component and should
                // be intergrated & combined with d1_cn_noderegistry inside
                // of the d1_cn_common package
                log.warn("Using D1Client to look up nodeList from CN");
                nodeList = D1Client.getCN().listNodes().getNodeList();
        }
        
        sessionSubject = session.getSubject();
        isAllowed = ServiceMethodRestrictionUtil.isMethodAllowed(sessionSubject, nodeList, "CNIdentity", "mapIdentity");
        if (!isAllowed) {
        	String sessionSubjectValue = null;
        	if (sessionSubject != null) {
        		sessionSubjectValue = sessionSubject.getValue();
        	}
			throw new NotAuthorized("2360", sessionSubjectValue  + " is not allowed to map identities");
        }
        
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
	        
	        String primaryDN = new LdapName(primarySubject.getValue()).toString();
	        String secondaryDN = new LdapName(secondarySubject.getValue()).toString();

	        // mark primary as having the equivalentIdentity
	        try {
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", secondaryDN);
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(primaryDN, mods);
		        log.debug("Successfully set equivalentIdentity on: " + primaryDN + " for " + secondaryDN);
	        } catch (Exception e) {
				// one failure is OK, two is not
		        log.warn("Could not set equivalentIdentity on: " + primaryDN + " for " + secondaryDN, e);
		        failureCount++;
			}
	        
        	// mark secondary as having the equivalentIdentity
	        try {
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentity", primaryDN);
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondaryDN, mods);
		        log.debug("Successfully set equivalentIdentity on: " + secondaryDN + " for " + primaryDN);
	        } catch (Exception e) {
				// one failure is OK, two is not
		        log.warn("Could not set equivalentIdentity on: " + secondaryDN + " for " + primaryDN, e);
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
		InvalidCredentials, NotImplemented, InvalidRequest, NotAuthorized {

		Subject subject = p.getSubject();

		// will throw an exception
		canEditPerson(session, subject);
		
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
		
		// checks if we are allowed to call this method -- should be very restricted
        List<Node> nodeList = null;
        try {
        	nodeList = nodeRegistryService.listNodes().getNodeList();
        } catch (Exception e) {
                // will only get here if running outside the context of the CN deployment
                log.warn("Using D1Client to look up nodeList from CN");
                nodeList = D1Client.getCN().listNodes().getNodeList();
        }
        
        Subject sessionSubject = session.getSubject();
        boolean isAllowed = ServiceMethodRestrictionUtil.isMethodAllowed(sessionSubject, nodeList, "CNIdentity", "verifyAccount");
        if (!isAllowed) {
        	String sessionSubjectValue = null;
        	if (sessionSubject != null) {
        		sessionSubjectValue = sessionSubject.getValue();
        	}
        	throw new NotAuthorized("4541", sessionSubjectValue + " is not allowed to verify identities");
        }

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
    	throws ServiceFailure, NotAuthorized, NotImplemented, NotFound {
		return getSubjectInfo(session, subject, true, subject.getValue());
	}
	
	private SubjectInfo getSubjectInfo(Session session, Subject subject, boolean recurse, String originatingSubject)
    	throws ServiceFailure, NotAuthorized, NotImplemented, NotFound {

		// check redaction policy
		boolean redact = shouldRedact(session);
		if (redact) {
			if (session != null) {
				log.debug("subjectInfo requested for: '" + subject.getValue() + "'");
				log.debug("checking if redaction holds for the calling user: '" + session.getSubject().getValue() + "'");
			} else {
				log.debug("session is null, we will redact email");
			}
			
			//if we are looking up our own info then don't redact
			if (session != null && session.getSubject().equals(subject)) {
				log.debug("subject MATCH. lifting redaction for the calling user: '" + session.getSubject().getValue() + "'");
				redact = false;
			}
		}
		
		SubjectInfo subjectInfo = new SubjectInfo();
        String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			subjectInfo = processAttributes(dn, attributes, recurse, false, redact, originatingSubject);
			log.debug("Retrieved SubjectList for: " + dn);
		} catch (NameNotFoundException ex) {
                    log.warn("Could not find: " + dn + " : in Ldap: " + ex.getMessage());
                    throw new NotFound("4564", ex.getMessage());
		} catch (Exception e) {
			String msg = "Problem looking up entry: " + dn + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("4561", msg);
		}

		return subjectInfo;
	}

	/**
	 * Given a Person, we need to find which Groups it is a member of
	 * @param personDn the Person dn for which we need membership information
	 * @return list of Groups the person belongs to
	 * @throws ServiceFailure
	 */
	protected List<Group> lookupGroups(String personDn) throws ServiceFailure {

		// check redaction policy
		boolean redact = false;
		
		SubjectInfo pList = new SubjectInfo();
		try {
			DirContext ctx = getContext();
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		    // search for all groups with the member subject
		    String searchCriteria = "(&(objectClass=groupOfUniqueNames)(uniqueMember=" + personDn + "))";

	        NamingEnumeration<SearchResult> results =
	            ctx.search(base, searchCriteria, ctls);

	        while (results != null && results.hasMore()) {
	            SearchResult si = results.next();
	            String dn = si.getNameInNamespace();
	            log.debug("Search result found for: " + dn);
	            Attributes attrs = si.getAttributes();
	            // DO NOT look up other details about matching Groups or Persons, nor include equivalentIdentity requests
	            SubjectInfo resultList = processAttributes(dn, attrs, false, false, redact, dn);
                if (resultList != null) {
                	// add groups
	                for (Group group: resultList.getGroupList()) {
		                pList.addGroup(group);
	                }
                }
	        }

	    } catch (Exception e) {
	    	String msg = "Problem looking up group membership at base: " + base + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("2290", msg);
	    }

	    return pList.getGroupList();
	}
	
	// TODO: use query and start/count params
	@Override
	public SubjectInfo listSubjects(Session session, String query, String status, Integer start,
	        Integer count) throws ServiceFailure, InvalidToken, NotAuthorized,
	        NotImplemented {

		// check redaction policy
		boolean redact = shouldRedact(session);
		
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
	            SubjectInfo resultList = processAttributes(dn, attrs, false, false, redact, dn);
                if (resultList != null) {
                	// add groups
	                for (Group group: resultList.getGroupList()) {
	                	if (!contains(pList.getGroupList(), group)) {
	                		pList.addGroup(group);
	                	}
	                }
	                // add people
	                for (Person person: resultList.getPersonList()) {
	                	if (!contains(pList.getPersonList(), person)) {
	                		pList.addPerson(person);
	                	}
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

	private SubjectInfo processAttributes(String name, Attributes attributes, 
			boolean recurse, boolean equivalentIdentityRequestsOnly, boolean redact, 
			String originatingSubject) throws Exception {

		SubjectInfo pList = new SubjectInfo();

		// convert to use the standardized string representation
		name = CertificateManager.getInstance().standardizeDN(name);
		originatingSubject = CertificateManager.getInstance().standardizeDN(originatingSubject);

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
							attributeValue = CertificateManager.getInstance().standardizeDN(attributeValue);
							Subject member = new Subject();
							member.setValue(attributeValue);
							group.addHasMember(member);
							log.debug("Found attribute: " + attributeName + "=" + attributeValue);
							// look up details for this Group member?
							if (recurse) {
								// only one level of recursion for groups
								SubjectInfo groupInfo = this.getSubjectInfo(null, member, false, originatingSubject);
								// has people as members?
								if (groupInfo.getPersonList() != null) {
									for (Person p: groupInfo.getPersonList()) {
										if (!contains(pList.getPersonList(), p)) {
											pList.addPerson(p);
										}
									}
								}
								// has other groups as members?
								if (groupInfo.getGroupList() != null) {
									for (Group g: groupInfo.getGroupList()) {
										if (!contains(pList.getGroupList(), g)) {
											pList.addGroup(g);
										}
									}
								}
							}
						}
					}
				}
				// only add if we don't already have it in the group list (from recursion)
				if (!contains(pList.getGroupList(), group)) {
					pList.getGroupList().add(0, group);
				}

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
								attributeValue = CertificateManager.getInstance().standardizeDN(attributeValue);
								Subject equivalentIdentityRequest = new Subject();
								equivalentIdentityRequest.setValue(attributeValue);
								log.debug("Found attribute: " + attributeName + "=" + attributeValue);
								// add this identity to the subject list?
								if (recurse) {
									// if we have recursed back to the original identity, then skip it
									if (originatingSubject != null && originatingSubject.equals(equivalentIdentityRequest.getValue())) {
										continue;
									}
									// catch the NotFound in case we only have the subject's DN
									try {
										// do not recurse for equivalent identity requests
										SubjectInfo equivalentIdentityRequestInfo = this.getSubjectInfo(null, equivalentIdentityRequest, false, originatingSubject);
										if (equivalentIdentityRequestInfo.getPersonList() != null) {
											for (Person p: equivalentIdentityRequestInfo.getPersonList()) {
												if (!contains(pList.getPersonList(), p)) {
													pList.addPerson(p);
												}
											}
										}
										if (equivalentIdentityRequestInfo.getGroupList() != null) {
											for (Group g: equivalentIdentityRequestInfo.getGroupList()) {
												if (!contains(pList.getGroupList(), g)) {
													pList.addGroup(g);
												}
											}
										}
									} catch (NotFound e) {
										// ignore NotFound
										log.warn("No account found for equivalentIdentityRequest entry: " + equivalentIdentityRequest.getValue(), e);
										// still add this placeholder
										Person placeholderPerson = new Person();
										placeholderPerson.setSubject(equivalentIdentityRequest);
										placeholderPerson.addEmail("NA");
										placeholderPerson.addGivenName("NA");
										placeholderPerson.setFamilyName("NA");
										if (!contains(pList.getPersonList(), placeholderPerson)) {
											pList.addPerson(placeholderPerson);
										}
									}
								}
							}
						}
					} else {
						if (attributeName.equalsIgnoreCase("equivalentIdentity")) {
							items = (NamingEnumeration<String>) attribute.getAll();
							while (items.hasMore()) {
								attributeValue = items.next();
								attributeValue = CertificateManager.getInstance().standardizeDN(attributeValue);
								Subject equivalentIdentity = new Subject();
								equivalentIdentity.setValue(attributeValue);
								person.addEquivalentIdentity(equivalentIdentity);
								log.debug("Found attribute: " + attributeName + "=" + attributeValue);
								// add this identity to the subject list
								if (recurse) {
									// if we have recurse back to the original identity, then skip it
									if (originatingSubject != null && originatingSubject.equals(equivalentIdentity.getValue())) {
										continue;
									}
									// allow case where the identity is not found
									try {
										// do not recurse for equivalent identities
										SubjectInfo equivalentIdentityInfo = this.getSubjectInfo(null, equivalentIdentity, false, originatingSubject);
										if (equivalentIdentityInfo.getPersonList() != null) {
											for (Person p: equivalentIdentityInfo.getPersonList()) {
												if (!contains(pList.getPersonList(), p)) {
													pList.addPerson(p);
												}
											}
										}
										if (equivalentIdentityInfo.getGroupList() != null) {
											for (Group g: equivalentIdentityInfo.getGroupList()) {
												if (!contains(pList.getGroupList(), g)) {
													pList.addGroup(g);
												}
											}
										}
									} catch (NotFound e) {
										// ignore NotFound
										log.warn("No account found for equivalentIdentity entry: " + equivalentIdentity.getValue(), e);
										// still add this placeholder
										Person placeholderPerson = new Person();
										placeholderPerson.setSubject(equivalentIdentity);
										placeholderPerson.addEmail("NA");
										placeholderPerson.addGivenName("NA");
										placeholderPerson.setFamilyName("NA");
										if (!contains(pList.getPersonList(), placeholderPerson)) {
											pList.addPerson(placeholderPerson);
										}
									}
								}
							}
						}
					}
					
				}
				
				// group membership
				List<Group> groups = lookupGroups(name);
				for (Group g: groups) {
					person.addIsMemberOf(g.getSubject());
					if (!contains(pList.getGroupList(), g)){
						pList.getGroupList().add(g);
					}
				}
				
				// add as the first one in the list
				if (!contains(pList.getPersonList(), person)) {
					pList.getPersonList().add(0, person);
				}
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
			NotImplemented {
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
			NotImplemented {
		
		// check redaction policy
		boolean redact = shouldRedact(session);
		if (redact) {
			if (session != null) {
				log.debug("subjectInfo requested for: '" + subject.getValue() + "'");
				log.debug("checking if redaction holds for the calling user: '" + session.getSubject().getValue() + "'");
			} else {
				log.debug("session is null, we will redact email");
			}
			
			//if we are looking up our own info then don't redact
			if (session != null && session.getSubject().equals(subject)) {
				log.debug("subject MATCH. lifting redaction for the calling user: '" + session.getSubject().getValue() + "'");
				redact = false;
			}
		}
		
		SubjectInfo subjectInfo = new SubjectInfo();
	    String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			// include the equivalent identity requests only
			subjectInfo = processAttributes(dn, attributes, true, true, redact, dn);
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
			NotImplemented {
		
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
                    e.printStackTrace();
	    	throw new ServiceFailure("2390", "Could not remove identity mapping: " + e.getMessage());
		}

		return true;
	}
	
	private boolean shouldRedact(Session session) throws NotImplemented, ServiceFailure {
		
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
							return false;
						}
					}
				}
			}
		} 
		return true;
	}
	
	private static boolean contains(List<Person> personList, Person person) {
		for (Person p: personList) {
			if (p.getSubject().equals(person.getSubject())) {
				return true;
			}
		}
		return false;
	}
	
	private static boolean contains(List<Group> groupList, Group group) {
		for (Group g: groupList) {
			if (g.getSubject().equals(group.getSubject())) {
				return true;
			}
		}
		return false;
	}

	public static void main(String[] args) {
		try {

			Subject p = new Subject();
			p.setValue("cn=testGroup2,dc=cilogon,dc=org");
//			p.setValue("CN=BRL,DC=cilogon,DC=org");

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer("ldap://bespin.nceas.ucsb.edu:389");
//			identityService.setServer("ldap://fred.msi.ucsb.edu:389");
			identityService.removeSubject(p);
//			SubjectInfo si = identityService.getSubjectInfo(null, p);
//			String subjectDn = si.getGroup(0).getGroupName();
//			System.out.println(subjectDn);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

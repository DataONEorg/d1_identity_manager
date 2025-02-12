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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.naming.InvalidNameException;
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
import org.dataone.client.auth.CertificateManager;
import org.dataone.client.v2.itk.D1Client;
import org.dataone.cn.ldap.DirContextProvider;
import org.dataone.cn.ldap.LDAPService;
import org.dataone.configuration.Settings;
import org.dataone.service.cn.v2.CNIdentity;
import org.dataone.service.cn.v2.impl.NodeRegistryServiceImpl;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v1.NodeType;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.types.v1.util.AuthUtils;
import org.dataone.service.types.v2.Node;
import org.dataone.service.types.v2.NodeList;
import org.dataone.service.types.v2.util.ServiceMethodRestrictionUtil;

/**
 * Proposed LDAP schema extensions
 *
 * objectClass: d1Principal
 * attributes:
 *		equivalentIdentity (0...n) - used when mapping is confirmed
 *		equivalentIdentityRequest (0...n) - used when mapping is requested (before confirmation)
 *		isVerified (1...1) - used when untrusted account is registered
 *
 * objectClass: d1Group
 * attributes:
 *		adminIdentity (0...n) - references other Principals that are allowed to modify the group
 *
 * @author leinfelder
 *
 */
public class CNIdentityLDAPImpl extends LDAPService implements CNIdentity {

	public static Log log = LogFactory.getLog(CNIdentityLDAPImpl.class);
	
	private static final Integer DEFAULT_COUNT = new Integer(100);

	private String subtree = Settings.getConfiguration().getString("identity.ldap.subtree", "dc=dataone");

	private static DirContextProvider dirContextProvider = DirContextProvider.getInstance();
	
    private NodeRegistryServiceImpl nodeRegistryService = new NodeRegistryServiceImpl();
    
	public CNIdentityLDAPImpl() {
		// we need to use a different base for the ids
		this.setBase(Settings.getConfiguration().getString("identity.ldap.base"));
	}
	
	
    @Override
    public Subject createGroup(Session session, Group group) throws ServiceFailure,
	    InvalidToken, NotAuthorized, NotImplemented,
	    IdentifierNotUnique, InvalidRequest {
		Subject groupSubject = null;
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			groupSubject = group.getSubject();
			String groupName = group.getGroupName();
			Subject groupAdmin = session.getSubject();
	
			// the DN for the group
			String dn = groupSubject.getValue();
			dn = constructDn(dn);
	
			/* objectClass groupOfUniqueNames....
			 * MUST ( uniqueMember $ cn )
			 * MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
			 */
			Attribute objClasses = new BasicAttribute("objectclass");
			objClasses.add("top");
			objClasses.add("groupOfUniqueNames");
			objClasses.add("uidObject");
			//objClasses.add("d1Group");
	
			// either it's in the dn, or we should construct it
			String commonName = parseAttribute(dn, "cn");
			if (commonName == null) {
				commonName = groupName;
			}
			Attribute cn = new BasicAttribute("cn", commonName);
			Attribute uid = new BasicAttribute("uid", groupSubject.getValue());
			Attribute desc = new BasicAttribute("description", groupName);
	
			// the creator is 'owner' by default
			Attribute owners = new BasicAttribute("owner");
			String groupAdminDn = constructDn(groupAdmin.getValue());
			owners.add(groupAdminDn);
			// add all other rightsHolders as 'owner' too
			if (group.getRightsHolderList() != null) {
				for (Subject rightsHolder : group.getRightsHolderList()) {
					String ownerDn = constructDn(rightsHolder.getValue());
					owners.add(ownerDn);
				}
			}
	
			// 'uniqueMember' is required, so always add the creator
			Attribute uniqueMembers = new BasicAttribute("uniqueMember");
			String adminDn = constructDn(groupAdmin.getValue());
			uniqueMembers.add(adminDn);
	
			// add all other members as 'uniqueMembers'
			if (group.getHasMemberList() != null) {
				for (Subject member : group.getHasMemberList()) {
					String memberValue = member.getValue();
					if (memberValue == null || memberValue.length() == 0) {
						throw new InvalidRequest("2542", "Group member cannot be blank");
					}
					String memberDn = constructDn(memberValue);
					// check if they are trying to add a group as a member
					boolean memberIsGroup = false;
					try {
						List<Object> values = this.getAttributeValues(dirContext, memberDn, "uniqueMember");
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
						uniqueMembers.add(memberDn);
					}
				}
			}
	
			try {
	
				Attributes orig = new BasicAttributes();
				orig.put(objClasses);
				orig.put(uid);
				orig.put(cn);
				orig.put(desc);
				orig.put(uniqueMembers);
				orig.put(owners);
				dirContext.createSubcontext(new LdapName(dn), orig);
				log.debug("Created group " + dn + ".");
				} catch (NameAlreadyBoundException e) {
					// If entry exists
					String msg = "Group " + dn + " already exists";
					log.warn(msg);
					throw new IdentifierNotUnique("2400", msg);
				//return false;
				} catch (NamingException e) {
					log.error(e.getMessage(),e);
					throw new ServiceFailure("2490", "Could not create group: " + e.getMessage());
			}
		} finally {
            log.info("1 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
		return groupSubject;
    }

    @Override
    public boolean updateGroup(Session session, Group group)
	    throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

		Subject groupSubject = group.getSubject();
	
		// back up the original before updating
		SubjectInfo originalGroup = this.getSubjectInfo(session, groupSubject);
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
	
			// will throw NotAuthorized if not true		
			boolean canEdit = canEditGroup(dirContext, session, groupSubject);
	
			// remove the group
			this.removeSubject(dirContext, groupSubject);
	
		} catch (NamingException e) {
			log.error(e.getMessage(),e);
			ServiceFailure sf = new ServiceFailure("2490", "Could not update group: " + e.getMessage());
			sf.initCause(e);
			throw sf;
		} finally {
            log.info("2 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
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
	
	private boolean canEditGroup(DirContext dirContext,Session session, Subject groupSubject) throws NamingException, NotAuthorized {
		// check that they have admin rights for group
		boolean canEdit = false;
		// collect all equivalent IDs for this session
		Collection<Subject> sessionSubjects = AuthUtils.authorizedClientSubjects(session);
	 
		String dn = constructDn(groupSubject.getValue());
		
		// find the admin list of the group
		List<Object> owners = this.getAttributeValues( dirContext, dn, "owner");
	 
		log.debug("owners.size=" + owners.size());

		// do any of our subjects match the owners?
		ownerSearch:
		for (Subject user: sessionSubjects) {
			String sessionSubject = user.getValue();
			try {
				sessionSubject = CertificateManager.getInstance().standardizeDN(sessionSubject);
			} catch (IllegalArgumentException ex) {
			// non-DNs are acceptable
			}
			log.debug("sessionSubject=" + sessionSubject);
			for (Object ownerObj: owners) {
				String owner = (String) ownerObj;
				log.debug("1. owner=" + owner);
				// either use the dn or look up the subject as housed in UID
				List<Object> uids = this.getAttributeValues( dirContext, owner, "uid");
				if (uids != null && uids.size() > 0) {
					owner = uids.get(0).toString();
				}
				log.debug("2. owner=" + owner);
				try {
					owner = CertificateManager.getInstance().standardizeDN(owner);
				} catch (IllegalArgumentException ex) {
					// non-DNs are acceptable
				}
				log.debug("3. owner=" + owner);

				log.debug(sessionSubject + " == " + owner + " ?: " + sessionSubject.equals(owner));
				if (sessionSubject.equals(owner)) {
					canEdit = true;
					break ownerSearch;
				}
			}
		}
		
		log.debug("canEdit=" + canEdit);

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
			String sessionSubject = user.getValue();
			try {
				sessionSubject = CertificateManager.getInstance().standardizeDN(sessionSubject);
			} catch (IllegalArgumentException ex) {
			// non-DNs are acceptable
			}
			String listedSubject = personSubject.getValue();
			try {
				listedSubject = CertificateManager.getInstance().standardizeDN(listedSubject);
			} catch (IllegalArgumentException ex) {
			// non-DNs are acceptable
			}
			if (sessionSubject.equals(listedSubject)) {
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
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			// checks if we are allowed to call this method -- should be very restricted
			List<Node> nodeList = null;
			try {
				nodeList = nodeRegistryService.listNodes().getNodeList();
			} catch (Exception e) {
	
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
				throw new NotAuthorized("2360", sessionSubjectValue + " is not allowed to map identities");
			}
	
			String dn = constructDn(primarySubject.getValue());
			String dn2 = constructDn(secondarySubject.getValue());
	
			// for handling special characters in the DN
			try {
				dn = new LdapName(dn).toString();
				dn2 = new LdapName(dn2).toString();
			} catch (InvalidNameException e) {
				throw new ServiceFailure("2390", "Could not properly escape DN: " + e.getMessage());
			}
	
			// check for pre-existing mapping
			boolean mappingExists
				= checkAttribute(dirContext, dn, "equivalentIdentity", secondarySubject.getValue());
			if (mappingExists) {
				throw new InvalidRequest("", "Account mapping already exists");
			}
	
			try {
	
				// get the context
				ModificationItem[] mods = null;
				Attribute mod0 = null;
		
				String primaryId = primarySubject.getValue();
				String secondaryId = secondarySubject.getValue();
		
				// mark primary as having the equivalentIdentity
				try {
					mods = new ModificationItem[1];
					mod0 = new BasicAttribute("equivalentIdentity", secondaryId);
					mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
					// make the change
					dirContext.modifyAttributes(new LdapName(dn), mods);
					log.debug("Successfully set equivalentIdentity on: " + primaryId + " for " + secondaryId);
				} catch (Exception e) {
					// one failure is OK, two is not
					log.warn("Could not set equivalentIdentity on: " + primaryId + " for " + secondaryId, e);
					failureCount++;
				}
		
				// mark secondary as having the equivalentIdentity
				try {
					mods = new ModificationItem[1];
					mod0 = new BasicAttribute("equivalentIdentity", primaryId);
					mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
					// make the change
					dirContext.modifyAttributes(new LdapName(dn2), mods);
					log.debug("Successfully set equivalentIdentity on: " + secondaryId + " for " + primaryId);
				} catch (Exception e) {
					// one failure is OK, two is not
					log.warn("Could not set equivalentIdentity on: " + secondaryId + " for " + primaryId, e);
					failureCount++;
				}
	
			} catch (Exception e) {
				log.error(e.getMessage(),e);
				throw new ServiceFailure("2390", "Could not map identity: " + e.getMessage());
			}
	
			// one account need not exist and this should still succeed
			if (failureCount > 1) {
				throw new ServiceFailure("2390", "Could not map identity, neither account could be edited.");
			}
		} finally {
            log.info("3 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
		return true;
    }
    
	
    @Override
    public boolean requestMapIdentity(Session session, Subject secondarySubject)
	    throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
	    NotImplemented, InvalidRequest {
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
	
		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();
	
			String dn = constructDn(primarySubject.getValue());
			String dn2 = constructDn(secondarySubject.getValue());
	
			// get the context
			// check if primary is registered
			boolean subjectExists = false;
			boolean confirmationRequested = false;
			try {
				subjectExists = checkAttribute(dirContext, dn, "cn", "*");
			} catch (Exception e) {
				subjectExists = false;
			}
			if (subjectExists) {
				// check if inverse request already exists
				confirmationRequested
					= checkAttribute(dirContext, dn, "equivalentIdentityRequest", secondarySubject.getValue());
				if (confirmationRequested) {
					throw new InvalidRequest("", "Request already issued for: " + primarySubject.getValue() + " = " + secondarySubject.getValue());
				}
			}
	
			// check if request already exists
			confirmationRequested
				= checkAttribute(dirContext, dn2, "equivalentIdentityRequest", primarySubject.getValue());
			if (confirmationRequested) {
				throw new InvalidRequest("", "Request already issued for: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
			}
	
			// make the request
			ModificationItem[] mods = null;
			Attribute mod0 = null;
			// mark secondary as having the equivalentIdentityRequest
			mods = new ModificationItem[1];
			mod0 = new BasicAttribute("equivalentIdentityRequest", primarySubject.getValue());
			mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
			// make the change
			dirContext.modifyAttributes(new LdapName(dn2), mods);
			log.debug("Successfully set equivalentIdentityRequest on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
		} catch (Exception e) {
			log.error(e.getMessage(),e);
			throw new ServiceFailure("2390", "Could not request map identity: " + e.getMessage());
		} finally {
            log.info("4 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
	
		return true;
    }

    @Override
    public boolean confirmMapIdentity(Session session, Subject secondarySubject)
	    throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
	    NotImplemented {
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();
	
			// get the context
	
			String dn = constructDn(primarySubject.getValue());
			String dn2 = constructDn(secondarySubject.getValue());
	
			// check if primary is confirming secondary
			boolean confirmationRequest
				= checkAttribute(dirContext, dn, "equivalentIdentityRequest", secondarySubject.getValue());
	
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
				dirContext.modifyAttributes(new LdapName(dn), mods);
				log.debug("Successfully set equivalentIdentity: " + primarySubject.getValue() + " = " + secondarySubject.getValue());
		
				// update attribute on secondarySubject
				boolean subjectExists = false;
				try {
					subjectExists = checkAttribute(dirContext, dn2, "cn", "*");
				} catch (Exception e) {
					subjectExists = false;
				}
				if (subjectExists) {
					mods = new ModificationItem[1];
					mod0 = new BasicAttribute("equivalentIdentity", primarySubject.getValue());
					mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
					// make the change
					dirContext.modifyAttributes(new LdapName(dn2), mods);
					log.debug("Successfully set reciprocal equivalentIdentity: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
				}
	
			} else {
				// no request to confirm
				throw new InvalidRequest("", "There is no identity mapping request to confim on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
			}
		} catch (Exception e) {
			log.error(e.getMessage(),e);
			throw new ServiceFailure("2390", "Could not confirm identity mapping: " + e.getMessage());
		} finally {
            log.info("5 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
	
		return true;
    }

    @Override
    public Subject updateAccount(Session session, Person p) throws ServiceFailure,
	    InvalidCredentials, NotImplemented, InvalidRequest, NotAuthorized {

		Subject subject = p.getSubject();
	
		// will throw an exception
		canEditPerson(session, subject);
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			// the DN
			String uidValue = subject.getValue();
	
			// ensure it is a DN
			String dn = constructDn(uidValue);
	
			// either it's in the dn, or we should construct it
			String commonName = parseAttribute(dn, "cn");
			if (commonName == null) {
				commonName = "";
				if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
					commonName += p.getGivenName(0) + " ";
				}
				commonName += p.getFamilyName();
			}
			Attribute uid = new BasicAttribute("uid", uidValue);
			Attribute cn = new BasicAttribute("cn", commonName);
			Attribute sn = new BasicAttribute("sn", p.getFamilyName());
			Attribute givenNames = new BasicAttribute("givenName");
			for (String givenName : p.getGivenNameList()) {
				givenNames.add(givenName);
			}
			Attribute mail = new BasicAttribute("mail");
			for (String email : p.getEmailList()) {
				mail.add(email);
			}
			// Update isVerified attribute to false again
			Attribute isVerified = new BasicAttribute("isVerified", Boolean.FALSE.toString().toUpperCase());
	
	
			// construct the list of modifications to make
			ModificationItem[] mods = new ModificationItem[6];
			mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, uid);
			mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, cn);
			mods[2] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, sn);
			mods[3] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, givenNames);
			mods[4] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mail);
			mods[5] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, isVerified);
	
			// make the change
			dirContext.modifyAttributes(new LdapName(dn), mods);
			log.debug("Updated entry: " + subject.getValue());
		} catch (Exception e) {
			log.error(e.getMessage(),e);
			throw new ServiceFailure("4530", "Could not update account: " + e.getMessage());
		} finally {
            log.info("6 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
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
		// Get a DirContext from the Context Pool
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			boolean isAllowed = false;
			Subject sessionSubject = null;
			if (session != null) {
				sessionSubject = session.getSubject();
				isAllowed = ServiceMethodRestrictionUtil.isMethodAllowed(sessionSubject, nodeList, "CNIdentity", "verifyAccount");
			}
			if (!isAllowed) {
				String sessionSubjectValue = null;
				if (sessionSubject != null) {
					sessionSubjectValue = sessionSubject.getValue();
				}
				throw new NotAuthorized("4541", sessionSubjectValue + " is not allowed to verify identities");
			}
	
			try {
				/* get a handle to an Initial DirContext */
		
				String dn = constructDn(subject.getValue());
		
				/* construct the list of modifications to make */
				ModificationItem[] mods = new ModificationItem[1];
				// Update isVerified attribute
				Attribute isVerified = new BasicAttribute("isVerified", Boolean.TRUE.toString().toUpperCase());
				mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, isVerified);
		
				/* make the change */
				dirContext.modifyAttributes(new LdapName(dn), mods);
				log.debug("Verified subject: " + subject.getValue());
			} catch (NamingException e) {
				log.error(e,e);
				throw new ServiceFailure("4540", "Could not verify account: " + e.getMessage());
			}
		} finally {
            log.info("7 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
		return true;
    }

	public String constructDn(String subject) {
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
	
    @Override
    public Subject registerAccount(Session session, Person p) throws ServiceFailure, IdentifierNotUnique, InvalidCredentials,
	    NotImplemented, InvalidRequest {

		// Get a DirContext from the Context Pool
		Subject subject = null;
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			// Values we'll use in creating the entry
			Attribute objClasses = new BasicAttribute("objectclass");
			objClasses.add("top");
			objClasses.add("person");
			objClasses.add("organizationalPerson");
			objClasses.add("inetOrgPerson");
			objClasses.add("d1Principal");
	
			// get the DN
			subject = p.getSubject();
			String uidValue = subject.getValue();
	
			// ensure it is a DN
			String dn = constructDn(uidValue);
	
			// construct the tree as needed
			try {
				constructTree(dirContext, dn);
			} catch (NamingException e) {
				log.error(e, e);
				throw new ServiceFailure("4520", "Could not construct partial tree: " + e.getMessage());
			}
	
			// either it's in the dn, or we should construct it
			String commonName = parseAttribute(dn, "cn");
			if (commonName == null) {
				commonName = "";
				if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
					commonName += p.getGivenName(0) + " ";
				}
				commonName += p.getFamilyName();
			}
	
			Attribute uid = new BasicAttribute("uid", uidValue);
			Attribute cn = new BasicAttribute("cn", commonName);
			Attribute sn = new BasicAttribute("sn", p.getFamilyName());
			Attribute givenNames = new BasicAttribute("givenName");
			for (String givenName : p.getGivenNameList()) {
				givenNames.add(givenName);
			}
			Attribute mail = new BasicAttribute("mail");
			if (p.getEmailList() != null) {
				for (String email : p.getEmailList()) {
					mail.add(email);
				}
			}
			Attribute isVerified = new BasicAttribute("isVerified", Boolean.FALSE.toString().toUpperCase());
	
			try {
				Attributes orig = new BasicAttributes();
				orig.put(objClasses);
				if (uid.getAll().hasMore()) {
					orig.put(uid);
				}
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
				dirContext.createSubcontext(new LdapName(dn), orig);
				log.debug("Added entry " + dn);
			} catch (NameAlreadyBoundException e) {
				String msg = "Entry " + dn + " already exists";
				// If entry exists already
				log.warn(msg, e);
				throw new IdentifierNotUnique("4521", msg);
			} catch (NamingException e) {
				log.error(e, e);
				throw new ServiceFailure("4520", "Could not register account: " + e.getMessage());
			}
		} finally {
            log.info("8 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
		return subject;
    }

    @Override
    public SubjectInfo getSubjectInfo(Session session, Subject subject)
	    throws ServiceFailure, NotAuthorized, NotImplemented, NotFound {
		SubjectInfo subjectInfo;
		// Get a DirContext from the Context Pool
	
		DirContext dirContext = null;
		try {
			dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);
			throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
			throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}
		try {
			List<String> visitedSubjects = new ArrayList<String>();
			visitedSubjects.add(subject.getValue());
	
			subjectInfo = getSubjectInfo(dirContext, session, subject, true, visitedSubjects);
		} finally {
            log.info("9 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
		}
		return subjectInfo;
    }
	
	private SubjectInfo getSubjectInfo(DirContext dirContext, Session session, Subject subject, boolean recurse, List<String> visitedSubjects)
	throws ServiceFailure, NotAuthorized, NotImplemented, NotFound {

		// check redaction policy
		boolean redact = shouldRedact(session);
		if (redact) {
		    if (log.isDebugEnabled()) {
		        if (session != null) {
		            log.debug("subjectInfo requested for: '" + subject.getValue() + "'");
		            log.debug("checking if redaction holds for the calling user: '" + session.getSubject().getValue() + "'");
		        } else {
		            log.debug("session is null, we will redact email");
		        }
		    }
			
			//if we are looking up our own info then don't redact
			if (session != null && session.getSubject().equals(subject)) {
				if (log.isDebugEnabled())
				    log.debug("subject MATCH. lifting redaction for the calling user: '" + session.getSubject().getValue() + "'");
				redact = false;
			}
		}
		
		SubjectInfo subjectInfo = new SubjectInfo();
		String uidValue = subject.getValue();
	
		// ensure DN
		String dn = constructDn(uidValue);

		try {
			Attributes attributes = dirContext.getAttributes(new LdapName(dn));
			subjectInfo = processAttributes(dirContext, dn, attributes, recurse, false, redact, visitedSubjects);
			if (log.isDebugEnabled())
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
	protected List<Group> lookupGroups(DirContext dirContext, String personDn) throws ServiceFailure {

		// check redaction policy
		boolean redact = false;
		
		SubjectInfo pList = new SubjectInfo();
		
		try {
			SearchControls ctls = new SearchControls();
		    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		    // search for all groups with the member subject
		    String searchCriteria = "(&(objectClass=groupOfUniqueNames)(uniqueMember=" + personDn + "))";

		    NamingEnumeration<SearchResult> results =
		    dirContext.search(this.getBase(), searchCriteria, ctls);

			List<String> visitedSubjects = new ArrayList<String>();
			while (results != null && results.hasMore()) {
				SearchResult si = results.next();
				String dn = si.getNameInNamespace();
				log.debug("Search result found for: " + dn);
				Attributes attrs = si.getAttributes();
				// DO NOT look up other details about matching Groups or Persons, nor include equivalentIdentity requests
					visitedSubjects.add(dn);
				SubjectInfo resultList = processAttributes(dirContext, dn, attrs, false, false, redact,visitedSubjects);
				if (resultList != null) {
					// add groups
					for (Group group: resultList.getGroupList()) {
						pList.addGroup(group);
					}
				}
			}

	    } catch (Exception e) {
			String msg = "Problem looking up group membership at base: " + this.getBase() + " : " + e.getMessage();
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
		if (start == null || start < 0) {
			start = 0;
	    }
		log.info("The start index is "+start.intValue());
		if (count == null || count <= 0) {
			log.info("The count is null or equal or less than 0===================");
			count = DEFAULT_COUNT;
			log.info("the count value is ==============="+count.intValue());
		} else {
			log.info("The count is not null or a positive number===================");
			log.info("the count value is ==============="+count.intValue());
		}
			SubjectInfo pList = new SubjectInfo();
		// Get a DirContext from the Context Pool

		DirContext dirContext = null;
		try {
		    dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
		    log.error(ex.getMessage(), ex);
		    throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
		    throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}

		try {
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
						"(uid=*" + query + "*)" +
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
				dirContext.search(this.getBase(), searchCriteria, ctls);
			int index =0;
			while (results != null && results.hasMore()) {
				SearchResult si = results.next();
				String dn = si.getNameInNamespace();
				log.debug("Search result found for: " + dn);
				Attributes attrs = si.getAttributes();
					// DO NOT look up other details about matching Groups or Persons, nor include equivalentIdentity requests
				List<String> visitedSubjects = new ArrayList<String>();
				visitedSubjects.add(dn);
				SubjectInfo resultList = processAttributes(dirContext, dn, attrs, false, false, redact, visitedSubjects);
				if (resultList != null) {
					// add groups
					for (Group group: resultList.getGroupList()) {
						if (!contains(pList.getGroupList(), group)) {
							if(index >= start && index < (count+start)) {
								pList.addGroup(group);
							}
						index++;
							
						}
					}
					// add people
					for (Person person: resultList.getPersonList()) {
						if (!contains(pList.getPersonList(), person)) {
							if(index >= start && index < (count+start)) {
								pList.addPerson(person);
							}
						index++;
						}
					}
				}
			}

	    } catch (Exception e) {
	    	String msg = "Problem listing entries at base: " + this.getBase() + " : " + e.getMessage();
	    	log.error(msg, e);
	    	throw new ServiceFailure("2290", msg);
	    } finally {
            log.info("11 returning DirContext");
	    	dirContextProvider.returnDirContext(dirContext);
	    }

	    return pList;
	}
	
//    @Override
//	public boolean isGroup(Session session, Subject subject) 
//	throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
//	SubjectInfo subjectInfo = this.getSubjectInfo(session, subject);
//	// we have a group
//	if (subjectInfo.getGroupList() != null && subjectInfo.getGroupList().size() > 0) {
//		// we have no people
//		if (subjectInfo.getPersonList() == null || subjectInfo.getPersonList().size() == 0) {
//			return true;
//		}
//	}
//	
//	return false;
//	
//    }
// 
//    @Override
//    public boolean isPublic(Session session, Subject subject) 
//    throws ServiceFailure, InvalidRequest, NotAuthorized, NotImplemented, NotFound {
//	return subject.getValue().equals(Constants.SUBJECT_PUBLIC);
//    }

	private SubjectInfo processAttributes(DirContext dirContext, String name, Attributes attributes, 
			boolean recurse, boolean equivalentIdentityRequestsOnly, boolean redact, 
			List<String> visitedSubjects) throws Exception {

		SubjectInfo pList = new SubjectInfo();

		// convert to use the standardized string representation
		try {
			name = CertificateManager.getInstance().standardizeDN(name);
		} catch (IllegalArgumentException ex) {
		// non-DNs are acceptable
		}	
		if (!visitedSubjects.contains(name)) {
			visitedSubjects.add(name);
		}

		if (attributes == null) {
		    return pList;
		}
		
		// deal with any attributes below...
		
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

		        if (attributeName.equalsIgnoreCase("uid")) {
		            attributeValue = (String) attribute.get();
		            group.getSubject().setValue(attributeValue);
		            if (log.isDebugEnabled()) 
		                log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		        }
		        if (attributeName.equalsIgnoreCase("cn")) {
		            if (log.isDebugEnabled()) 
		                log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		            attributeValue = (String) attribute.get();
		            // only set if we don't have it from descption
		            if (group.getGroupName() == null) {
		                group.setGroupName(attributeValue);
		            }
		        }
		        if (attributeName.equalsIgnoreCase("description")) {
		            attributeValue = (String) attribute.get();
		            group.setGroupName(attributeValue);
		            if (log.isDebugEnabled()) 
		                log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		        }
		        if (attributeName.equalsIgnoreCase("owner")) {
		            items = (NamingEnumeration<String>) attribute.getAll();
		            while (items.hasMore()) {
		                attributeValue = items.next();
		                if (log.isDebugEnabled()) 
		                    log.debug("Found attribute: " + attributeName + "=" + attributeValue);

		                // either the dn or look up the subject as housed in UID
		                String subjectId = attributeValue;
		                List<Object> uids = this.getAttributeValues(dirContext, attributeValue, "uid");
		                if (uids != null && uids.size() > 0) {
		                    subjectId = uids.get(0).toString();
		                } else {
		                    subjectId = CertificateManager.getInstance().standardizeDN(attributeValue);
		                }

		                Subject owner = new Subject();
		                owner.setValue(subjectId);
		                group.addRightsHolder(owner);
		            }
		        }
		        if (attributeName.equalsIgnoreCase("uniqueMember")) {
		            items = (NamingEnumeration<String>) attribute.getAll();
		            while (items.hasMore()) {
		                attributeValue = items.next();

		                // either the dn or look up the subject as housed in UID
		                String subjectId = attributeValue;
		                List<Object> uids = this.getAttributeValues(dirContext, attributeValue, "uid");
		                if (uids != null && uids.size() > 0) {
		                    subjectId = uids.get(0).toString();
		                } else {
		                    subjectId = CertificateManager.getInstance().standardizeDN(attributeValue);
		                }

		                Subject member = new Subject();
		                member.setValue(subjectId);
		                group.addHasMember(member);

		                // look up details for this Group member?
		                if (recurse) {
		                    // only one level of recursion for groups
		                    SubjectInfo groupInfo = null;
		                    try {
		                        groupInfo = this.getSubjectInfo(dirContext, null, member, false, visitedSubjects);
		                    } catch (NotFound nf) {
		                        log.warn("could not find member DN: " + subjectId);
		                        continue;
		                    }

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
		    // not a group...
		    // process as a person
		    Person person = new Person();
		    Subject subject = new Subject();
		    subject.setValue(name); // will replace with UID attribute
		    person.setSubject(subject);

		    while (values.hasMore()) {
		        Attribute attribute = values.next();
		        String attributeName = attribute.getID();
		        String attributeValue = null;

		        if (attributeName.equalsIgnoreCase("uid")) {
		            attributeValue = (String) attribute.get();
		            if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		            person.getSubject().setValue(attributeValue);
		        }
		        if (attributeName.equalsIgnoreCase("cn")) {
		            attributeValue = (String) attribute.get();
		            if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		        }
		        if (attributeName.equalsIgnoreCase("sn")) {
		            attributeValue = (String) attribute.get();
		            person.setFamilyName(attributeValue);
		            if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		        }
		        if (attributeName.equalsIgnoreCase("mail")) {
		            // should email be redacted?
		            if (!redact) {
		                items = (NamingEnumeration<String>) attribute.getAll();
		                while (items.hasMore()) {
		                    attributeValue = items.next();
		                    person.addEmail(attributeValue);
		                    if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		                }
		            }

		        }
		        if (attributeName.equalsIgnoreCase("givenName")) {
		            items = (NamingEnumeration<String>) attribute.getAll();
		            while (items.hasMore()) {
		                attributeValue = items.next();
		                person.addGivenName(attributeValue);
		                if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		            }
		        }
		        if (attributeName.equalsIgnoreCase("isVerified")) {
		            attributeValue = (String) attribute.get();
		            person.setVerified(Boolean.parseBoolean(attributeValue));
		            if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);
		        }
		        // do we care about the requests or just the confirmed ones?
		        if (equivalentIdentityRequestsOnly) {
		            if (attributeName.equalsIgnoreCase("equivalentIdentityRequest")) {
		                items = (NamingEnumeration<String>) attribute.getAll();
		                while (items.hasMore()) {
		                    attributeValue = items.next();						


		                    // try to look it up
		                    Subject equivalentIdentityRequest = new Subject();														     
		                    equivalentIdentityRequest.setValue(attributeValue);
		                    if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + attributeValue);

		                    // add this identity to the subject list?
		                    if (recurse) {
		                        // if we have recursed back to the original identity, then skip it
		                        if (visitedSubjects != null && visitedSubjects.contains(equivalentIdentityRequest.getValue())) {
		                            continue;
		                        }
		                        // catch the NotFound in case we only have the subject's DN
		                        try {
		                            // do not recurse for equivalent identity requests
		                            SubjectInfo equivalentIdentityRequestInfo = this.getSubjectInfo(dirContext, null, equivalentIdentityRequest, false, visitedSubjects);
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
		        } else if (attributeName.equalsIgnoreCase("equivalentIdentity")) {
		            items = (NamingEnumeration<String>) attribute.getAll();
		            while (items.hasMore()) {
		                attributeValue = items.next();
		                String equivalentIdentityName = attributeValue;
		                // The name passed in that is the subject's value
		                // The equivalent identity should be treated in the 
		                // same way as the named subject, meaning that 
		                // the equivalent identity should be standardized as
		                // well (otherwise infinite recursion and StackOverflow)

		                // convert to use the standardized string representation
		                try {
		                    equivalentIdentityName = CertificateManager.getInstance().standardizeDN(equivalentIdentityName);
		                } catch (IllegalArgumentException ex) {
		                    // non-DNs are acceptable
		                }	


		                if (log.isDebugEnabled()) log.debug("Found attribute: " + attributeName + "=" + equivalentIdentityName);

		                Subject equivalentIdentity = new Subject();

		                // add as equivalent
		                equivalentIdentity.setValue(equivalentIdentityName);
		                person.addEquivalentIdentity(equivalentIdentity);

		                // add this identity to the subject list
		                if (recurse) {
		                    // if we have recurse back to the original identity, then skip it
		                    if (visitedSubjects != null && visitedSubjects.contains(equivalentIdentity.getValue())) {
		                        continue;
		                    }
		                    // allow case where the identity is not found
		                    try {
		                        // recurse for equivalent identities
		                        SubjectInfo equivalentIdentityInfo = this.getSubjectInfo(dirContext, null, equivalentIdentity, true, visitedSubjects);
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

		    // group membership
		    List<Group> groups = lookupGroups(dirContext, name);
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

		return pList;
	}

	protected boolean removeSubject(DirContext dirContext, Subject p) {
		String dn = constructDn(p.getValue());
		return super.removeEntry(dirContext,dn);
	}
	
	@Override
	public boolean denyMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {
	// Get a DirContext from the Context Pool

		DirContext dirContext = null;
		try {
		    dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
		    log.error(ex.getMessage(), ex);
		    throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
		    throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}

		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

			// get the context

			String dn = constructDn(primarySubject.getValue());
		
			// check if primary has the request from secondary
			boolean confirmationRequest =
				checkAttribute(dirContext, dn, "equivalentIdentityRequest", secondarySubject.getValue());
	
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
				dirContext.modifyAttributes(new LdapName(dn), mods);
				if (log.isDebugEnabled()) 
				    log.debug("Successfully removed equivalentIdentityRequest on: " + primarySubject.getValue() + " for " + secondarySubject.getValue());
			}
	
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			throw new ServiceFailure("2390", "Could not deny the identity mapping: " + e.getMessage());
		} finally {
            log.info("12 returning DirContext");
			dirContextProvider.returnDirContext(dirContext);
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
		    if (log.isDebugEnabled()) {
		        if (session != null) {
		            log.debug("subjectInfo requested for: '" + subject.getValue() + "'");
		            log.debug("checking if redaction holds for the calling user: '" + session.getSubject().getValue() + "'");
		        } else {
		            log.debug("session is null, we will redact email");
		        }
		    }
			
			//if we are looking up our own info then don't redact
			if (session != null && session.getSubject().equals(subject)) {
			    if (log.isDebugEnabled()) 
			        log.debug("subject MATCH. lifting redaction for the calling user: '" + session.getSubject().getValue() + "'");
				redact = false;
			}
		}
		
		SubjectInfo subjectInfo = new SubjectInfo();
	    String dn = subject.getValue();
	    // ensure DN
	    dn = constructDn(dn);
	    // Get a DirContext from the Context Pool

		DirContext dirContext = null;
		try {
		    dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
		    log.error(ex.getMessage(), ex);
		    throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
		    throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}

		try {
			Attributes attributes = dirContext.getAttributes(new LdapName(dn));
			List<String> visitedSubjects = new ArrayList<String>();
			visitedSubjects.add(dn);
			// include the equivalent identity requests only
			subjectInfo = processAttributes(dirContext, dn, attributes, true, true, redact, visitedSubjects);
			if (log.isDebugEnabled()) log.debug("Retrieved SubjectList for: " + dn);
		} catch (Exception e) {
			String msg = "Problem looking up entry: " + dn + " : " + e.getMessage();
			log.error(msg, e);
			throw new ServiceFailure("4561", msg);
	    } finally {
            log.info("13 returning DirContext");
	    	dirContextProvider.returnDirContext(dirContext);
	    }

		return subjectInfo;
		
	}
	
	@Override
	public boolean removeMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {
	// Get a DirContext from the Context Pool

		DirContext dirContext = null;
		try {
		    dirContext = dirContextProvider.borrowDirContext();
		} catch (Exception ex) {
		    log.error(ex.getMessage(), ex);
		    throw new ServiceFailure("2490", ex.getMessage());
		}
		if (dirContext == null) {
		    throw new ServiceFailure("2490", "Context is null. Unable to retrieve LDAP Directory Context from pool. Please try again.");
		}		
		try {
			// primary subject in the session
			Subject primarySubject = session.getSubject();

			String dn = constructDn(primarySubject.getValue());
		    String dn2 = constructDn(secondarySubject.getValue());
		   

		    // check if primary has secondary equivalence
		    boolean mappingExists =
			checkAttribute(dirContext, dn, "equivalentIdentity", secondarySubject.getValue());
		    boolean reciprocolMappingExists =
			checkAttribute(dirContext, dn2, "equivalentIdentity", primarySubject.getValue());

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
					dirContext.modifyAttributes(new LdapName(dn), mods);
					if (log.isDebugEnabled()) 
					    log.debug("Successfully removed equivalentIdentity: " + primarySubject.getValue() + " = " + secondarySubject.getValue());
				}
				
				// remove attribute on secondarySubject
				if (reciprocolMappingExists) {
					mods = new ModificationItem[1];
					mod0 = new BasicAttribute("equivalentIdentity", primarySubject.getValue());
					mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
					// make the change
					dirContext.modifyAttributes(new LdapName(dn2), mods);
					if (log.isDebugEnabled()) 
					    log.debug("Successfully removed reciprocal equivalentIdentity: " + secondarySubject.getValue() + " = " + primarySubject.getValue());
				}
			
		    } else {
		    	// neither mapping is valid
				throw new InvalidRequest("", "There is no identity mapping between: " + primarySubject.getValue() + " and " + secondarySubject.getValue());
		    }

		} catch (Exception e) {
			log.error(e, e);
		    throw new ServiceFailure("2390", "Could not remove identity mapping: " + e.getMessage());
	    } finally {
            log.info("14 returning DirContext");
	    	dirContextProvider.returnDirContext(dirContext);
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
//			identityService.setServer("ldap://bespin.nceas.ucsb.edu:389");
//			identityService.setServer("ldap://fred.msi.ucsb.edu:389");
//			identityService.removeSubject(p);
//			SubjectInfo si = identityService.getSubjectInfo(null, p);
//			String subjectDn = si.getGroup(0).getGroupName();
//			System.out.println(subjectDn);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

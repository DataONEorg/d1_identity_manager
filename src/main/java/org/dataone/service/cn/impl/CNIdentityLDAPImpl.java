package org.dataone.service.cn.impl;

import java.util.ArrayList;
import java.util.Enumeration;
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
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.service.cn.CNIdentity;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.Group;
import org.dataone.service.types.Person;
import org.dataone.service.types.Session;
import org.dataone.service.types.Subject;
import org.dataone.service.types.SubjectList;


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
	private String base = "dc=dataone,dc=org";

	public boolean createGroup(Session session, Subject groupName) throws ServiceFailure,
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
	        // If entry exists already, fine.  Ignore this error.
	    	log.warn("Group " + dn + " already exists, no need to create");
	        //return false;
	    } catch (NamingException e) {
	    	log.error("Problem creating group." + e);
	        return false;
	    }
	    
		return true;
	}
	
    public boolean addGroupMembers(Session session, Subject groupName, SubjectList members) 
    	throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {
    	
    	try {
	        
	        // check that they have admin rights for group
	        Subject user = session.getSubject();
	        boolean canEdit = this.checkAttribute(groupName, "owner", user.getValue());
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
	        	boolean isMember = this.checkAttribute(groupName, "uniqueMember", subject.getValue());
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
	        throw new ServiceFailure(null, e.getMessage());
	    }
    	
    	return true;
    	
    }
    
    public boolean removeGroupMembers(Session session, Subject groupName, SubjectList members) 
		throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {
		
		try {
	        
	        // check that they have admin rights for group
	        Subject user = session.getSubject();
	        boolean canEdit = this.checkAttribute(groupName, "owner", user.getValue());
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
	        throw new ServiceFailure(null, e.getMessage());
	    }
		
		return true;
		
	}

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
	        	checkAttribute(primarySubject, "equivalentIdentityRequest", secondarySubject.getValue());
	        
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
	        	// mark secondary as having the equivalentIdentityRequest
		        mods = new ModificationItem[1];
		        mod0 = new BasicAttribute("equivalentIdentityRequest", primarySubject.getValue());
		        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
		        // make the change
		        ctx.modifyAttributes(secondarySubject.getValue(), mods);
		        log.debug("Successfully set equivalentIdentityRequest on: " + secondarySubject.getValue() + " for " + primarySubject.getValue());
		    
	        }
	        
		} catch (Exception e) {
			log.error("Could not map identity", e);
	        return false;
	    }		
		
		return true;
	}
	
	public Subject updateAccount(Session session, Person p) throws ServiceFailure, 
		IdentifierNotUnique, InvalidCredentials, NotImplemented, InvalidRequest {
		
		Subject subject = p.getSubject();

		try {
			String commonName = "";
		    if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
		    	commonName += p.getGivenName(0) + " "; 
		    }
		    commonName += p.getFamilyName();;
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
		    ctx.modifyAttributes(subject.getValue(), mods);
		    log.debug( "Updated entry: " + subject.getValue() );
		} catch (Exception e) {
		    throw new ServiceFailure(null, e.getMessage());
		}		
		
		return subject;
	}

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
	        throw new ServiceFailure(null, e.getMessage());
	    }		
		
		return true;
	}

	public Subject registerAccount(Session session, Person p) {
	    // Values we'll use in creating the entry
	    Attribute objClasses = new BasicAttribute("objectclass");
	    objClasses.add("top");
	    objClasses.add("person");
	    objClasses.add("organizationalPerson");
	    objClasses.add("inetOrgPerson");
	    objClasses.add("d1Principal");
	    String commonName = "";
	    if (p.getGivenNameList() != null && !p.getGivenNameList().isEmpty()) {
	    	commonName += p.getGivenName(0) + " "; 
	    }
	    commonName += p.getFamilyName();;
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

	    // Specify the DN we're adding
	    // TODO: do we create the subject, or is it a given?
	    Subject subject = p.getSubject();
	    String dn = subject.getValue();
	   
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
	        // If entry exists already, fine.  Ignore this error. 
	    	log.warn("Entry " + dn + " already exists, no need to add", e);
	        //return false;
	    } catch (NamingException e) {
	    	log.error("Problem adding entry: " + dn, e);
	        return null;
	    }
		return subject;
	}
	
	public SubjectList getSubjectInfo(Session session, Subject subject)
		throws ServiceFailure, InvalidToken {

		SubjectList pList = new SubjectList();
	    String dn = subject.getValue();
		try {
			DirContext ctx = getContext();
			Attributes attributes = ctx.getAttributes(dn);
			pList = processAttributes(dn, attributes);
			log.debug("Retrieved SubjectList for: " + dn);
		} catch (Exception e) {
	    	log.error("Problem looking up entry: " + dn, e);
		}
		
		return pList;
	}
	
	// TODO: use query and start/count params
	public SubjectList listSubjects(Session session, String query, int start, int count)
	    throws ServiceFailure, InvalidToken, NotAuthorized, NotImplemented {

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
	        
	    } catch (NamingException e) {
	    	log.error("Problem listing entries at base: " + base, e);
	    }
	    
	    return pList;
	}
	
	private SubjectList processAttributes(String name, Attributes attributes) {
		
		SubjectList pList = new SubjectList();

		try {
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
		} catch (Exception e) {
	    	log.error("Problem processing attributes", e);
		}
		return pList;
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

	public boolean removeSubject(Subject p) {
		try {
			DirContext ctx = getContext();
			ctx.destroySubcontext(p.getValue());
	    	log.debug("Removed entry: " + p.getValue());
	    } catch (NamingException e) {
	    	log.error("Error removing entry: " + p.getValue(), e);
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
	
	private String parseAttribute(String original, String attribute) {
		String result = original;
		result = result.substring(result.indexOf( attribute + "="), result.indexOf(","));
		result = result.substring(result.indexOf("=") + 1) ;
		return result;
	}
	
	public static void main(String[] args) {
		try {
			
			Subject p = new Subject();
			p.setValue("cn=testGroup,dc=dataone,dc=org");
		
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.removeSubject(p);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

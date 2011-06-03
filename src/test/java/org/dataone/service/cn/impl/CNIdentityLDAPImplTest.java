package org.dataone.service.cn.impl;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.dataone.service.cn.impl.CNIdentityLDAPImpl;
import org.dataone.service.types.Person;
import org.dataone.service.types.Session;
import org.dataone.service.types.Subject;
import org.dataone.service.types.SubjectList;
import org.junit.Test;

/**
 *
 * @author leinfelder
 */
public class CNIdentityLDAPImplTest {
	
	private String server = "ldap://fred.msi.ucsb.edu:389";
	private String serverReplica = "ldap://bespin.nceas.ucsb.edu:389";
	private int replicationDelay = 5000; // milliseconds

	private String primarySubject = "cn=test1,dc=dataone,dc=org";
	private String secondarySubject = "cn=test2,dc=dataone,dc=org";
	private String groupName = "cn=testGroup,dc=dataone,dc=org";

	private static Session getSession(Subject subject) {
		Session session = new Session();
		session.setSubject(subject);
		return session;
	}
	
	@Test
	public void checkOneWayReplication()  {
	
		try {
			
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			
			boolean check = false;
			
			// wait for replication to occur
			Thread.sleep(replicationDelay);
			
			// check it on the other server
			identityService.setServer(serverReplica);
			check = identityService.checkAttribute(p, "isVerified", "FALSE");
			assertTrue(check);
			
			//clean up
			identityService.setServer(server);
			check = identityService.removeSubject(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
    @Test
    public void checkOtherWayReplication()  {

    	try {
    		
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(serverReplica);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			
			boolean check = false;
			
			// wait for replication to occur
			Thread.sleep(replicationDelay);
			
			// check it on the other server
			identityService.setServer(server);
			check = identityService.checkAttribute(p, "isVerified", "FALSE");
			assertTrue(check);
			
			//clean up
			identityService.setServer(serverReplica);
			check = identityService.removeSubject(p);
			assertTrue(check);

    	} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroup()  {

    	try {
			Subject p1 = new Subject();
			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");
			
			Subject p2 = new Subject();
			p2.setValue(secondarySubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			
			Subject groupSubject = new Subject();
			groupSubject.setValue(groupName);
			
			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addPerson(person2);
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();		
			boolean check = false;
			
			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);
			
			// group
			check = identityService.createGroup(getSession(p1), groupSubject);
			assertTrue(check);
			check = identityService.addGroupMembers(getSession(p1), groupSubject, members);
			assertTrue(check);
			check = identityService.removeGroupMembers(getSession(p1), groupSubject, members);
			assertTrue(check);
			
			// clean up (this is not required for service to be functioning)
			check = identityService.removeSubject(p1);
			assertTrue(check);
			check = identityService.removeSubject(p2);
			assertTrue(check);
			check = identityService.removeSubject(groupSubject);
			assertTrue(check);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }

	@Test
	public void mapIdentity()  {
	
		try {
			Subject p1 = new Subject();
			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");
			
			Subject p2 = new Subject();
			p2.setValue(secondarySubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();		
			boolean check = false;
			
			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);
			
			// map p1 to p2
			check = identityService.mapIdentity(getSession(p1), p2);
			assertTrue(check);
			// check pending
			check = identityService.checkAttribute(p2, "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// request is one-way
			check = identityService.checkAttribute(p1, "equivalentIdentityRequest", p2.getValue());
			assertFalse(check);
			// not yet confirmed on either end
			check = identityService.checkAttribute(p1, "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = identityService.checkAttribute(p2, "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);
			
			// double check reciprocal mapping
			check = identityService.checkAttribute(p1, "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = identityService.checkAttribute(p2, "equivalentIdentity", p1.getValue());
			assertTrue(check);
			
			// clean up (this is not required for service to be functioning)
			check = identityService.removeSubject(p1);
			assertTrue(check);
			check = identityService.removeSubject(p2);
			assertTrue(check);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}

	@Test
	public void verifySubject()  {
	
		try {
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			//person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			
			boolean check = false;
			check = identityService.verifyAccount(getSession(subject), p);
			assertTrue(check);
			check = identityService.checkAttribute(p, "isVerified", "TRUE");
			assertTrue(check);
			
			//clean up
			check = identityService.removeSubject(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
	@Test
	public void updateAccount()  {
	
		try {
			String newEmailAddress = "test2@dataone.org";
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			
			boolean check = false;
			// check that new email is NOT there
			check = identityService.checkAttribute(p, "mail", newEmailAddress);
			assertFalse(check);
			
			// change their email address, check that it is there
			person.clearEmailList();
			person.addEmail(newEmailAddress);
			p = identityService.updateAccount(getSession(subject), person);
			assertNotNull(p);
			check = identityService.checkAttribute(p, "mail", newEmailAddress);
			assertTrue(check);
			
			//clean up
			check = identityService.removeSubject(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
	@Test
	public void subjectInfo()  {
	
		try {
			
			// test that this email address is saved and retrieved
			String email = "test1@dataone.org";
			
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail(email);
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			
			boolean check = false;
			SubjectList subjectList = identityService.getSubjectInfo(getSession(subject), p);
			assertNotNull(subjectList);
			check = subjectList.getPerson(0).getEmail(0).equals(email);
			assertTrue(check);
			
			//clean up
			check = identityService.removeSubject(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
	@Test
	public void listSubjects()  {
	
		try {
			
			// test that this email address is saved and retrieved
			String email = "test1@dataone.org";
			
			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail(email);
			
			Subject groupSubject = new Subject();
			groupSubject.setValue(groupName);
			
			SubjectList members = new SubjectList();
			members.addPerson(person);
			
			boolean check = false;

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			check = identityService.createGroup(getSession(subject), groupSubject);
			assertTrue(check);
//			check = identityService.addGroupMembers(getSession(subject), groupSubject, members);
//			assertTrue(check);
			
			// check the subjects exist
			SubjectList subjectList = identityService.listSubjects(getSession(subject), null, -1, -1);
			assertNotNull(subjectList);
			check = subjectList.getPerson(0).getEmail(0).equalsIgnoreCase(email);
			assertTrue(check);
			check = subjectList.getGroup(0).getSubject().getValue().equalsIgnoreCase(groupName);
			assertTrue(check);
			
			//clean up
			check = identityService.removeSubject(p);
			assertTrue(check);
//			check = identityService.removeSubject(groupSubject);
//			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
}
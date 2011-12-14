package org.dataone.service.cn.impl.v1;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.dataone.client.D1Client;
import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.types.v1.Node;
import org.dataone.service.types.v1.NodeType;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.types.v1.SubjectList;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author leinfelder
 */
public class CNIdentityLDAPImplTest {

	// use Configuration to look up testing values
	private String server = Settings.getConfiguration().getString("test.ldap.server.1");
	private String serverReplica = Settings.getConfiguration().getString("test.ldap.server.1");
	private int replicationDelay = Settings.getConfiguration().getInt("test.replicationDelay"); // milliseconds
	private int replicationAttempts = Settings.getConfiguration().getInt("test.replicationAttempts");

	private String primarySubject = Settings.getConfiguration().getString("test.primarySubject");
	private String secondarySubject = Settings.getConfiguration().getString("test.secondarySubject");
	private String groupName = Settings.getConfiguration().getString("test.groupName");

	private static Session getSession(Subject subject) {
		Session session = new Session();
		session.setSubject(subject);
		return session;
	}
	
	/**
	 * Do our best to remove all the entries we may have inserted
	 * If we don't remove test entries, the tests can fail the next time they are run
	 */
	@After
	public void cleanUp() {
		CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
		identityService.setServer(server);
		try {
			identityService.removeEntry(primarySubject);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			identityService.removeEntry(secondarySubject);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			identityService.removeEntry(groupName);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	@Ignore
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
			int count = 0;
			// check it on the other server
			identityService.setServer(serverReplica);
			while (!check) {
				// wait for replication to occur
				Thread.sleep(replicationDelay);
				check = identityService.checkAttribute(p.getValue(), "isVerified", "FALSE");
				count++;
				if (count >= replicationAttempts) {
					break;
				}
			}
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

	@Ignore
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
			int count = 0;
			// check it on the server
			identityService.setServer(server);
			while (!check) {
				// wait for replication to occur
				Thread.sleep(replicationDelay);
				check = identityService.checkAttribute(p.getValue(), "isVerified", "FALSE");
				count++;
				if (count >= replicationAttempts) {
					break;
				}
			}
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
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(server);
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), groupSubject);
			assertNotNull(retGroup);
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
	public void mapIdentityTwoWay()  {

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
			identityService.setServer(server);
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// map p1 to p2
			check = identityService.requestMapIdentity(getSession(p1), p2);
			assertTrue(check);
			// check pending
			check = identityService.checkAttribute(p2.getValue(), "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// request is one-way
			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentityRequest", p2.getValue());
			assertFalse(check);
			// not yet confirmed on either end
			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = identityService.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);

			// double check reciprocal mapping
			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = identityService.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
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
			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			check = identityService.verifyAccount(getSession(subject), p);
			assertTrue(check);
			check = identityService.checkAttribute(p.getValue(), "isVerified", "TRUE");
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
			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			// check that new email is NOT there
			check = identityService.checkAttribute(p.getValue(), "mail", newEmailAddress);
			assertFalse(check);

			// change their email address, check that it is there
			person.clearEmailList();
			person.addEmail(newEmailAddress);
			p = identityService.updateAccount(getSession(subject), person);
			assertNotNull(p);
			check = identityService.checkAttribute(p.getValue(), "mail", newEmailAddress);
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
			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			SubjectInfo subjectInfo = identityService.getSubjectInfo(getSession(subject), p);
			assertNotNull(subjectInfo);
			check = subjectInfo.getPerson(0).getEmail(0).equals(email);
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
			members.addSubject(person.getSubject());

			boolean check = false;

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(subject), groupSubject);
			assertNotNull(retGroup);
//			check = identityService.addGroupMembers(getSession(subject), groupSubject, members);
//			assertTrue(check);

			// check the subjects exist
			SubjectInfo subjectInfo = identityService.listSubjects(getSession(subject), null, null, 0, -1);
			assertNotNull(subjectInfo);
			check = subjectInfo.getPerson(0).getEmail(0).equalsIgnoreCase(email);
			assertTrue(check);
			check = subjectInfo.getGroup(0).getSubject().getValue().equalsIgnoreCase(groupName);
			assertTrue(check);

			//clean up
			check = identityService.removeSubject(p);
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
			identityService.setServer(server);
			boolean check = false;
	
			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);
	
			// map p1 to p2, as non admin
			try {
				check = identityService.mapIdentity(getSession(p1), p1, p2);
			} catch (NotAuthorized na) {
				// expected this
				assertTrue(true);
				check = false;
			}
			assertFalse(check);
			
			// try as the CN
			Subject cnSubject = null;
			for (Node node: D1Client.getCN().listNodes().getNodeList()) {
				if (node.getType().equals(NodeType.CN)) {
					cnSubject = node.getSubject(0);
					break;
				}
			}
			check = identityService.mapIdentity(getSession(cnSubject ), p1, p2);
			assertTrue(check);
	
			// check mapping
			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = identityService.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
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

}

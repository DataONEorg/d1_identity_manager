package org.dataone.service.cn.tier2.impl;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.dataone.service.types.Person;
import org.dataone.service.types.Principal;
import org.dataone.service.types.PrincipalList;
import org.junit.Test;

/**
 *
 * @author waltz
 */
public class CNIdentityLDAPImplTest {
	
	private String server = "ldap://fred.msi.ucsb.edu:389";
	private String serverReplica = "ldap://bespin.nceas.ucsb.edu:389";

	private String primaryPrincipal = "cn=test1,dc=dataone,dc=org";
	private String secondaryPrincipal = "cn=test2,dc=dataone,dc=org";
	private String groupPrincipal = "cn=testGroup,dc=dataone,dc=org";

	
	@Test
	public void checkOneWayReplication()  {
	
		try {
			
			Principal principal = new Principal();
			principal.setValue(primaryPrincipal);
			Person person = new Person();
			person.setPrincipal(principal);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(server);
			Principal p = identityService.registerAccount(person);
			assertNotNull(p);
			
			boolean check = false;
			
			// wait for replication to occur
			Thread.sleep(5000);
			
			// check it on the other server
			identityService.setServer(serverReplica);
			check = identityService.checkAttribute(p, "isVerified", "FALSE");
			assertTrue(check);
			
			//clean up
			identityService.setServer(server);
			check = identityService.removePrincipal(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
    @Test
    public void checkOtherWayReplication()  {

    	try {
    		
			Principal principal = new Principal();
			principal.setValue(primaryPrincipal);
			Person person = new Person();
			person.setPrincipal(principal);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			identityService.setServer(serverReplica);
			Principal p = identityService.registerAccount(person);
			assertNotNull(p);
			
			boolean check = false;
			
			// wait for replication to occur
			Thread.sleep(5000);
			
			// check it on the other server
			identityService.setServer(server);
			check = identityService.checkAttribute(p, "isVerified", "FALSE");
			assertTrue(check);
			
			//clean up
			identityService.setServer(serverReplica);
			check = identityService.removePrincipal(p);
			assertTrue(check);

    	} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroup()  {

    	try {
			Principal p1 = new Principal();
			p1.setValue(primaryPrincipal);
			Person person1 = new Person();
			person1.setPrincipal(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");
			
			Principal p2 = new Principal();
			p2.setValue(secondaryPrincipal);
			Person person2 = new Person();
			person2.setPrincipal(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			
			Principal groupName = new Principal();
			groupName.setValue(groupPrincipal);
			
			PrincipalList members = new PrincipalList();
			members.addPerson(person1);
			members.addPerson(person2);
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();		
			boolean check = false;
			
			// create principals
			Principal principal = identityService.registerAccount(person1);
			assertNotNull(principal);
			principal = identityService.registerAccount(person2);
			assertNotNull(principal);
			
			// group
			check = identityService.createGroup(groupName);
			assertTrue(check);
			check = identityService.addGroupMembers(groupName, members);
			assertTrue(check);
			check = identityService.removeGroupMembers(groupName, members);
			assertTrue(check);
			
			// clean up (this is not required for service to be functioning)
			check = identityService.removePrincipal(p1);
			assertTrue(check);
			check = identityService.removePrincipal(p2);
			assertTrue(check);
			check = identityService.removePrincipal(groupName);
			assertTrue(check);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }

	@Test
	public void mapIdentity()  {
	
		try {
			Principal p1 = new Principal();
			p1.setValue(primaryPrincipal);
			Person person1 = new Person();
			person1.setPrincipal(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");
			
			Principal p2 = new Principal();
			p2.setValue(secondaryPrincipal);
			Person person2 = new Person();
			person2.setPrincipal(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();		
			boolean check = false;
			
			// create principals
			Principal principal = identityService.registerAccount(person1);
			assertNotNull(principal);
			principal = identityService.registerAccount(person2);
			assertNotNull(principal);
			
			// map p1 to p2
			check = identityService.mapIdentity(p1, p2);
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
			check = identityService.mapIdentity(p2, p1);
			assertTrue(check);
			
			// double check reciprocal mapping
			check = identityService.checkAttribute(p1, "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = identityService.checkAttribute(p2, "equivalentIdentity", p1.getValue());
			assertTrue(check);
			
			// clean up (this is not required for service to be functioning)
			check = identityService.removePrincipal(p1);
			assertTrue(check);
			check = identityService.removePrincipal(p2);
			assertTrue(check);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}

	@Test
	public void verifyPrincipal()  {
	
		try {
			Principal principal = new Principal();
			principal.setValue(primaryPrincipal);
			Person person = new Person();
			person.setPrincipal(principal);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail("test1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Principal p = identityService.registerAccount(person);
			assertNotNull(p);
			
			boolean check = false;
			check = identityService.verifyAccount(p);
			assertTrue(check);
			check = identityService.checkAttribute(p, "isVerified", "TRUE");
			assertTrue(check);
			
			//clean up
			check = identityService.removePrincipal(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
	@Test
	public void principalInfo()  {
	
		try {
			
			// test that this email address is saved and retrieved
			String email = "test1@dataone.org";
			
			Principal principal = new Principal();
			principal.setValue(primaryPrincipal);
			Person person = new Person();
			person.setPrincipal(principal);
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail(email);
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			Principal p = identityService.registerAccount(person);
			assertNotNull(p);
			
			boolean check = false;
			PrincipalList principalList = identityService.getPrincipalInfo(p);
			assertNotNull(principalList);
			check = principalList.getPerson(0).getEmail(0).equals(email);
			assertTrue(check);
			
			//clean up
			check = identityService.removePrincipal(p);
			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}

	
}

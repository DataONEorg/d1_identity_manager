package org.dataone.service.cn.tier2.impl;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.dataone.service.types.Person;
import org.dataone.service.types.Principal;
import org.junit.Test;

/**
 *
 * @author waltz
 */
public class CNIdentityLDAPImplTest {
	
	private String primaryPrincipal = "cn=test1,dc=nceas,dc=ucsb,dc=edu";
	private String secondaryPrincipal = "cn=test2,dc=nceas,dc=ucsb,dc=edu";
	private String groupPrincipal = "cn=testGroup,dc=nceas,dc=ucsb,dc=edu";

	
    @Test
    public void verifyPrincipal()  {

    	try {
			Principal principal = new Principal();
			principal.setValue(primaryPrincipal);
			Person person = new Person();
			person.setPrincipal(principal);
			person.setFamilyName("test1");
			person.setGivenNames(Arrays.asList(new String[] {"test1"}));
			
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
			fail();
			e.printStackTrace();
		}

    }
    
    @Test
    public void createGroup()  {

    	try {
			Principal p1 = new Principal();
			p1.setValue(primaryPrincipal);
			Person person1 = new Person();
			person1.setPrincipal(p1);
			person1.setFamilyName("test1");
			person1.setGivenNames(Arrays.asList(new String[] {"test1"}));
			
			Principal p2 = new Principal();
			p2.setValue(secondaryPrincipal);
			Person person2 = new Person();
			person2.setPrincipal(p2);
			person2.setFamilyName("test2");
			person2.setGivenNames(Arrays.asList(new String[] {"test1"}));
			
			Principal groupName = new Principal();
			groupName.setValue(groupPrincipal);
			
			List<Principal> members = new ArrayList<Principal>();
			members.add(p1);
			members.add(p2);
			
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
}

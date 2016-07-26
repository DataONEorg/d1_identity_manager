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


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v2.Node;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;
import org.dataone.service.types.v1.SubjectList;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

import org.dataone.service.types.v1.NodeReference;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.auth.CertificateManager;
import org.dataone.cn.ldap.LDAPTestIdentityCleanUp;
import org.dataone.service.cn.v2.impl.NodeRegistryServiceImpl;
import org.dataone.service.util.TypeMarshaller;
/**
 *
 * @author leinfelder
 */
public class CNIdentityLDAPImplTestUnit {

	// use Configuration to look up testing values
    public static Log log = LogFactory.getLog(CNIdentityLDAPImplTestUnit.class);
	private String primarySubject = Settings.getConfiguration().getString("test.primarySubject");
	private String secondarySubject = Settings.getConfiguration().getString("test.secondarySubject");
	private String orcidSubject = Settings.getConfiguration().getString("test.orcidSubject");
	private String groupName = Settings.getConfiguration().getString("test.groupName");
	private String secondaryGroupName = Settings.getConfiguration().getString("test.secondaryGroupName");
	private String groupSubjectNonDn = Settings.getConfiguration().getString("test.nonDnGroup.subject");
	private String groupNameNonDn = Settings.getConfiguration().getString("test.nonDnGroup.name");
	private String cnAdmin = "CN=l0c1Test,DC=dataone,DC=org";

	private String primarySubjectNonStandard = Settings.getConfiguration().getString("test.primarySubject.nonStandard");
	private String secondarySubjectNonStandard = Settings.getConfiguration().getString("test.secondarySubject.nonStandard");
        
    NodeRegistryServiceImpl nodeRegistryService = new NodeRegistryServiceImpl();
    LDAPTestIdentityCleanUp ldapTestIdentityCleanup = new LDAPTestIdentityCleanUp();
    
        final static int SIZE = 16384;
        
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
//		identityService.setServer(server);
		try {
			ldapTestIdentityCleanup.removeEntry(primarySubject);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			ldapTestIdentityCleanup.removeEntry(secondarySubject);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			ldapTestIdentityCleanup.removeEntry(groupName);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
    @Test
    public void editGroupMissingMember()  {

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
			
			Group group = new Group();
			group.setGroupName(groupName);
			group.setSubject(groupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
			boolean check = false;

			// create only 1 subject
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			
			// check that we can retrieve the group
			SubjectInfo subjects = identityService.listSubjects(null, null, null, null, null);
			assertNotNull(subjects);
			SubjectInfo existingGroup = identityService.getSubjectInfo(getSession(p1), groupSubject);
			assertNotNull(existingGroup);
			assertTrue(existingGroup.getGroup(0).getHasMemberList().contains(p2));

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
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
			
			Group group = new Group();
			group.setGroupName(groupName);
			group.setSubject(groupSubject);
			
			Subject secondaryGroupSubject = new Subject();
			secondaryGroupSubject.setValue(secondaryGroupName);
			
			Group secondaryGroup = new Group();
			secondaryGroup.setGroupName(secondaryGroupName);
			secondaryGroup.setSubject(secondaryGroupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
			boolean check = false;
            log.info("1 identityService.registerAccount");
			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
            log.info("2 identityService.registerAccount");
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
            log.info("3 identityService.createGroup");
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
            
			group.setHasMemberList(members.getSubjectList());
            log.info("4 identityService.updateGroup");
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			// remove members
			group.setHasMemberList(null);
            log.info("5 identityService.updateGroup");
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			
			// create secondary group
            log.info("6 identityService.createGroup");
			retGroup = identityService.createGroup(getSession(p1), secondaryGroup);
			assertNotNull(retGroup);
			
			// attempt to add members that are a Group (should fail)
			members.getSubjectList().add(secondaryGroupSubject);
			group.setHasMemberList(members.getSubjectList());
			check = false;
			try {
                log.info("7 identityService.updateGroup");
				check = identityService.updateGroup(getSession(p1), group);
			} catch (InvalidRequest e) {
				// expected exception
			}
			assertFalse(check);

			// clean up (this is not required for service to be functioning)
            log.info("8 ldapTestIdentityCleanup.removeSubject");
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
            log.info("9 ldapTestIdentityCleanup.removeSubject");
			check = ldapTestIdentityCleanup.removeSubject(p2);
			assertTrue(check);
            log.info("10 ldapTestIdentityCleanup.removeSubject");
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);
            log.info("11 ldapTestIdentityCleanup.removeSubject");
			check = ldapTestIdentityCleanup.removeSubject(secondaryGroupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroupNonDn()  {

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
			groupSubject.setValue(groupSubjectNonDn);
			
			Group group = new Group();
			group.setGroupName(groupNameNonDn);
			group.setSubject(groupSubject);
			
			Subject secondaryGroupSubject = new Subject();
			secondaryGroupSubject.setValue(secondaryGroupName);
			
			Group secondaryGroup = new Group();
			secondaryGroup.setGroupName(secondaryGroupName);
			secondaryGroup.setSubject(secondaryGroupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			// remove members
			group.setHasMemberList(null);
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			
			// create secondary group
			retGroup = identityService.createGroup(getSession(p1), secondaryGroup);
			assertNotNull(retGroup);
			
			// attempt to add members that are a Group (should fail)
			members.getSubjectList().add(secondaryGroupSubject);
			group.setHasMemberList(members.getSubjectList());
			check = false;
			try {
				check = identityService.updateGroup(getSession(p1), group);
			} catch (InvalidRequest e) {
				// expected exception
			}
			assertFalse(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(p2);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(secondaryGroupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroupOrcidNonDn()  {

    	try {
			Subject p1 = new Subject();
			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			Subject p2 = new Subject();
			p2.setValue(orcidSubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");

			Subject groupSubject = new Subject();
			groupSubject.setValue(groupSubjectNonDn);
			
			Group group = new Group();
			group.setGroupName(groupNameNonDn);
			group.setSubject(groupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			// remove members
			group.setHasMemberList(null);
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeEntry(identityService.constructDn(p2.getValue()));
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroupOrcid()  {

    	try {
			Subject p1 = new Subject();
			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			Subject p2 = new Subject();
			p2.setValue(orcidSubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");

			Subject groupSubject = new Subject();
			groupSubject.setValue(groupName);
			
			Group group = new Group();
			group.setGroupName(groupName);
			group.setSubject(groupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			// remove members
			group.setHasMemberList(null);
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeEntry(identityService.constructDn(p2.getValue()));
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }
    
    @Test
    public void editGroupMultipleOwners()  {

		boolean check = false;
		Subject p1 = new Subject();
		Subject p2 = new Subject();
		Subject groupSubject = new Subject();
		CNIdentityLDAPImpl identityService = null;


    	try {
    		
    		identityService = new CNIdentityLDAPImpl();

			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			p2.setValue(orcidSubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");

			groupSubject.setValue(groupName);
			
			Group group = new Group();
			group.setGroupName(groupName);
			group.setSubject(groupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());


			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			
			// try to modify the group as non-owner
			group.setHasMemberList(null);
			try {
				check = identityService.updateGroup(getSession(p2), group);
			} catch (NotAuthorized e) {
				// expected result
				check = false;
			}
			assertFalse(check);
			
			// add the secondary as another owner
			group.addRightsHolder(p2);
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			
			// modify as secondary owner
			group.setHasMemberList(null);
			check = identityService.updateGroup(getSession(p2), group);
			assertTrue(check);

			

		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
    	finally {
    		try {
	    		// clean up (this is not required for service to be functioning)
				check = ldapTestIdentityCleanup.removeSubject(p1);
				assertTrue(check);
				check = ldapTestIdentityCleanup.removeEntry(identityService.constructDn(p2.getValue()));
				assertTrue(check);
				check = ldapTestIdentityCleanup.removeSubject(groupSubject);
				assertTrue(check);
    		} catch (Exception e) {
    			e.printStackTrace();
    			fail();
    		}
    	}

    }
    
    @Test
    public void editGroupOrcidReverse()  {

    	try {
			Subject p1 = new Subject();
			p1.setValue(orcidSubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			Subject p2 = new Subject();
			p2.setValue(primarySubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");

			Subject groupSubject = new Subject();
			groupSubject.setValue(groupName);
			
			Group group = new Group();
			group.setGroupName(groupName);
			group.setSubject(groupSubject);

			// only add the secondary person because p1 is owner (member by default)
			SubjectList members = new SubjectList();
			//members.addPerson(person1);
			members.addSubject(person2.getSubject());

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			boolean check = false;

			// create subjects
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);

			// group
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(p1), group);
			assertNotNull(retGroup);
			// add members
			group.setHasMemberList(members.getSubjectList());
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);
			// remove members
			group.setHasMemberList(null);
			check = identityService.updateGroup(getSession(p1), group);
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeEntry(identityService.constructDn(p1.getValue()));
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeEntry(identityService.constructDn(p2.getValue()));
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

    }

	@Test
	public void mapIdentityTwoWay()  throws Exception  {
		try {
                    
                    ByteArrayOutputStream cnNodeOutput = new ByteArrayOutputStream();

                    InputStream is = this.getClass().getResourceAsStream("/org/dataone/resources/samples/v2/cnNode.xml");

                    BufferedInputStream bInputStream = new BufferedInputStream(is);
                    byte[] barray = new byte[SIZE];
                    int nRead = 0;
                    while ((nRead = bInputStream.read(barray, 0, SIZE)) != -1) {
                        cnNodeOutput.write(barray, 0, nRead);
                    }
                    bInputStream.close();
                    ByteArrayInputStream bArrayInputStream = new ByteArrayInputStream(cnNodeOutput.toByteArray());
                    Node testCNNode = TypeMarshaller.unmarshalTypeFromStream(Node.class, bArrayInputStream);

                    NodeReference cnNodeReference = testCNNode.getIdentifier();
                    try {
                    	nodeRegistryService.getNodeCapabilities(testCNNode.getIdentifier());
                    } catch (NotFound nf) {
                    	cnNodeReference = nodeRegistryService.register(testCNNode);
                    }
                    
                    assertNotNull(cnNodeReference);
                    testCNNode.setIdentifier(cnNodeReference);
                    nodeRegistryService.approveNode(cnNodeReference);

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
//			identityService.setServer(server);
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
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// request is one-way
//			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentityRequest", p2.getValue());
//			assertFalse(check);
			// not yet confirmed on either end
			check = ldapTestIdentityCleanup.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);

			// double check reciprocal mapping
			check = ldapTestIdentityCleanup.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(p2);
			assertTrue(check);
                        nodeRegistryService.deleteNode(cnNodeReference);
                        
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void mapIdentityTwoWayOrcid()  throws Exception  {

		try {
                    
			ByteArrayOutputStream cnNodeOutput = new ByteArrayOutputStream();
			InputStream is = this.getClass().getResourceAsStream("/org/dataone/resources/samples/v2/cnNode.xml");
			
			BufferedInputStream bInputStream = new BufferedInputStream(is);
			byte[] barray = new byte[SIZE];
			int nRead = 0;
			while ((nRead = bInputStream.read(barray, 0, SIZE)) != -1) {
			    cnNodeOutput.write(barray, 0, nRead);
			}
			bInputStream.close();
			ByteArrayInputStream bArrayInputStream = new ByteArrayInputStream(cnNodeOutput.toByteArray());
			Node testCNNode = TypeMarshaller.unmarshalTypeFromStream(Node.class, bArrayInputStream);
			
			NodeReference cnNodeReference = testCNNode.getIdentifier();
			try {
				nodeRegistryService.getNodeCapabilities(testCNNode.getIdentifier());
			} catch (NotFound nf) {
				cnNodeReference = nodeRegistryService.register(testCNNode);
			}
			
			assertNotNull(cnNodeReference);
			testCNNode.setIdentifier(cnNodeReference);
			nodeRegistryService.approveNode(cnNodeReference);

			Subject p1 = new Subject();
			p1.setValue(primarySubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			Subject p2 = new Subject();
			p2.setValue(orcidSubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			
			String dn1 = identityService.constructDn(primarySubject);
			String dn2 = identityService.constructDn(orcidSubject);

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
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// not yet confirmed on either end
			check = ldapTestIdentityCleanup.checkAttribute(dn1, "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);

			// double check reciprocal mapping
			check = ldapTestIdentityCleanup.checkAttribute(dn1, "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentity", p1.getValue());
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeEntry(dn1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeEntry(dn2);
			assertTrue(check);
                        nodeRegistryService.deleteNode(cnNodeReference);
                        
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void mapIdentityTwoWayOrcidReverse()  throws Exception  {
		try {
                    
			ByteArrayOutputStream cnNodeOutput = new ByteArrayOutputStream();
			InputStream is = this.getClass().getResourceAsStream("/org/dataone/resources/samples/v2/cnNode.xml");
			
			BufferedInputStream bInputStream = new BufferedInputStream(is);
			byte[] barray = new byte[SIZE];
			int nRead = 0;
			while ((nRead = bInputStream.read(barray, 0, SIZE)) != -1) {
			    cnNodeOutput.write(barray, 0, nRead);
			}
			bInputStream.close();
			ByteArrayInputStream bArrayInputStream = new ByteArrayInputStream(cnNodeOutput.toByteArray());
			Node testCNNode = TypeMarshaller.unmarshalTypeFromStream(Node.class, bArrayInputStream);
			
			NodeReference cnNodeReference = testCNNode.getIdentifier();
			try {
				nodeRegistryService.getNodeCapabilities(testCNNode.getIdentifier());
			} catch (NotFound nf) {
				cnNodeReference = nodeRegistryService.register(testCNNode);
			}
			
			assertNotNull(cnNodeReference);
			testCNNode.setIdentifier(cnNodeReference);
			nodeRegistryService.approveNode(cnNodeReference);

			Subject p1 = new Subject();
			p1.setValue(orcidSubject);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");

			Subject p2 = new Subject();
			p2.setValue(primarySubject);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");
			

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			
			String dn1 = identityService.constructDn(orcidSubject);
			String dn2 = identityService.constructDn(primarySubject);

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
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// not yet confirmed on either end
			check = ldapTestIdentityCleanup.checkAttribute(dn1, "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);

			// double check reciprocal mapping
			check = ldapTestIdentityCleanup.checkAttribute(dn1, "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = ldapTestIdentityCleanup.checkAttribute(dn2, "equivalentIdentity", p1.getValue());
			assertTrue(check);

			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeEntry(dn1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeEntry(dn2);
			assertTrue(check);
                        nodeRegistryService.deleteNode(cnNodeReference);
                        
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
//			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			Subject cnSubject = new Subject();
			cnSubject.setValue(cnAdmin);
			check = identityService.verifyAccount(getSession(cnSubject), p);
			assertTrue(check);
			check = ldapTestIdentityCleanup.checkAttribute(p.getValue(), "isVerified", "TRUE");
			assertTrue(check);

			//clean up
			check = ldapTestIdentityCleanup.removeSubject(p);
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
//			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			// check that new email is NOT there
			check = ldapTestIdentityCleanup.checkAttribute(p.getValue(), "mail", newEmailAddress);
			assertFalse(check);

			// change their email address, check that it is there
			person.clearEmailList();
			person.addEmail(newEmailAddress);
			p = identityService.updateAccount(getSession(subject), person);
			assertNotNull(p);
			check = ldapTestIdentityCleanup.checkAttribute(p.getValue(), "mail", newEmailAddress);
			assertTrue(check);

			//clean up
			check = ldapTestIdentityCleanup.removeSubject(p);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

	@Test
	public void subjectInfo()  {

		try {

			// test that the Email  is redacted, only CN subjects can see email addresses
			String email = "test1@dataone.org";

			Subject subject = new Subject();
			subject.setValue(primarySubject);
			Person person = new Person();
			person.setSubject(subject);
                        // test that the Given Name is saved and retrieved
			person.setFamilyName("test1");
			person.addGivenName("test1");
			person.addEmail(email);

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			SubjectInfo subjectInfo = identityService.getSubjectInfo(getSession(subject), p);
			assertNotNull(subjectInfo);

			check = subjectInfo.getPerson(0).getGivenName(0).equals("test1");
			assertTrue(check);

            assertTrue(subjectInfo.getPerson(0).sizeEmailList() == 1);
			//clean up
			check = ldapTestIdentityCleanup.removeSubject(p);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void updateOrcidAccount()  {

		try {
			String newEmailAddress = "test2@dataone.org";
			Subject subject = new Subject();
			subject.setValue(orcidSubject);
			Person person = new Person();
			person.setSubject(subject);
			person.setFamilyName("orcid1");
			person.addGivenName("orcid1");
			person.addEmail("orcid1@dataone.org");
			
			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
			
			String dn = identityService.constructDn(subject.getValue());
			Subject dnSubject = new Subject();
			dnSubject.setValue(dn);
			
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);

			boolean check = false;
			// check that new email is NOT there
			check = ldapTestIdentityCleanup.checkAttribute(dn, "mail", newEmailAddress);
			assertFalse(check);

			// change their email address, check that it is there
			person.clearEmailList();
			person.addEmail(newEmailAddress);
			p = identityService.updateAccount(getSession(subject), person);
			assertNotNull(p);
			check = ldapTestIdentityCleanup.checkAttribute(dn, "mail", newEmailAddress);
			assertTrue(check);

			//clean up
			check = ldapTestIdentityCleanup.removeSubject(dnSubject);
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
			
			Group group = new Group();
			group.setSubject(groupSubject);
			group.setGroupName(groupName);
			group.setHasMemberList(members.getSubjectList());

			boolean check = false;

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
			Subject p = identityService.registerAccount(getSession(subject), person);
			assertNotNull(p);
			Subject retGroup = null;
			retGroup = identityService.createGroup(getSession(subject), group);
			assertNotNull(retGroup);
//			check = identityService.updateGroup(getSession(subject), group);
//			assertTrue(check);

			// check the subjects exist
			SubjectInfo subjectInfo = identityService.listSubjects(getSession(subject), null, null, 0, -1);
                        assertNotNull(subjectInfo);
                        boolean personCheck = false;
                        for (Person checkPerson : subjectInfo.getPersonList()) {
                            if (checkPerson.getFamilyName().equals("test1")) {
                                personCheck = true;
                                // make certain email is redacted
                                assertTrue(checkPerson.sizeEmailList() == 0);
                            }
                        }
                        assertNotNull(personCheck);
                        boolean groupCheck = false;
                        for (Group checkGroup : subjectInfo.getGroupList()) {
                            if (checkGroup.getGroupName().equals(groupName)) {
                             groupCheck = true;
                            }
                        }
                        assertNotNull(groupCheck);
			//clean up
			check = ldapTestIdentityCleanup.removeSubject(p);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(groupSubject);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

	@Test
	public void mapIdentity() throws Exception  {

		try {
            log.info("mapIdentity()-");
            ByteArrayOutputStream cnNodeOutput = new ByteArrayOutputStream();

            InputStream is = this.getClass().getResourceAsStream("/org/dataone/resources/samples/v2/cnNode.xml");

            BufferedInputStream bInputStream = new BufferedInputStream(is);
            byte[] barray = new byte[SIZE];
            int nRead = 0;
            while ((nRead = bInputStream.read(barray, 0, SIZE)) != -1) {
                cnNodeOutput.write(barray, 0, nRead);
            }
            bInputStream.close();
            ByteArrayInputStream bArrayInputStream = new ByteArrayInputStream(cnNodeOutput.toByteArray());
            Node testCNNode = TypeMarshaller.unmarshalTypeFromStream(Node.class, bArrayInputStream);
            
            NodeReference cnNodeReference = testCNNode.getIdentifier();
            try {
            	nodeRegistryService.getNodeCapabilities(testCNNode.getIdentifier());
            } catch (NotFound nf) {
            	cnNodeReference = nodeRegistryService.register(testCNNode);
            }
            assertNotNull(cnNodeReference);
            testCNNode.setIdentifier(cnNodeReference);
            nodeRegistryService.approveNode(cnNodeReference);
            
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
//			identityService.setServer(server);
			boolean check = false;
	
			// create subjects
            log.info("mapIdentity()-identityService.registerAccount");
			Subject subject = identityService.registerAccount(getSession(p1), person1);
			assertNotNull(subject);
            log.info("mapIdentity()-identityService.registerAccount");
			subject = identityService.registerAccount(getSession(p2), person2);
			assertNotNull(subject);
	
			// map p1 to p2, as non admin
			try {
                log.info("mapIdentity()-identityService.mapIdentity");
				check = identityService.mapIdentity(getSession(p1), p1, p2);
			} catch (NotAuthorized na) {
				// expected this
				assertTrue(true);
				check = false;
			}
			assertFalse(check);
			
			// try as the CN
			Subject cnSubject = testCNNode.getSubject(0);
			cnSubject.setValue(cnAdmin);
            log.info("mapIdentity()-identityService.mapIdentity");
			check = identityService.mapIdentity(getSession(cnSubject), p1, p2);
			assertTrue(check);
	
			// check mapping
            log.info("mapIdentity()-checkAttribute(p1.getValue");
			check = ldapTestIdentityCleanup.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertTrue(check);
            log.info("mapIdentity()-checkAttribute(p2.getValue");
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertTrue(check);
	
			// clean up (this is not required for service to be functioning)
            log.info("mapIdentity()-removeSubject(p1)");
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
            log.info("mapIdentity()-removeSubject(p2)");
			check = ldapTestIdentityCleanup.removeSubject(p2);
			assertTrue(check);
            log.info("mapIdentity()-deleteNode");
                        nodeRegistryService.deleteNode(cnNodeReference);
                        log.info("mapIdentity()-Finished");
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
        /*
         * When there are two identities with nonstandard DNs (that could be standardized) in LDAP 
         * that were equivalent, if a Standardized DN of an identity is 
         * passed into the getSubjectInfo via Session and Subject (as would appear in a cert)
         * then  getSubjectInfo would create a StackOverflow exception because of
         * infinite recursion
         * See https://redmine.dataone.org/issues/7604
         */
	@Test
	public void getSubjectInfoIdentityTwoWay()  throws Exception  {
		try {
                    
                    ByteArrayOutputStream cnNodeOutput = new ByteArrayOutputStream();

                    InputStream is = this.getClass().getResourceAsStream("/org/dataone/resources/samples/v2/cnNode.xml");

                    BufferedInputStream bInputStream = new BufferedInputStream(is);
                    byte[] barray = new byte[SIZE];
                    int nRead = 0;
                    while ((nRead = bInputStream.read(barray, 0, SIZE)) != -1) {
                        cnNodeOutput.write(barray, 0, nRead);
                    }
                    bInputStream.close();
                    ByteArrayInputStream bArrayInputStream = new ByteArrayInputStream(cnNodeOutput.toByteArray());
                    Node testCNNode = TypeMarshaller.unmarshalTypeFromStream(Node.class, bArrayInputStream);

                    NodeReference cnNodeReference = testCNNode.getIdentifier();
                    try {
                    	nodeRegistryService.getNodeCapabilities(testCNNode.getIdentifier());
                    } catch (NotFound nf) {
                    	cnNodeReference = nodeRegistryService.register(testCNNode);
                    }
                    
                    assertNotNull(cnNodeReference);
                    testCNNode.setIdentifier(cnNodeReference);
                    nodeRegistryService.approveNode(cnNodeReference);

                    	Subject p1 = new Subject();
			p1.setValue(primarySubjectNonStandard);
			Person person1 = new Person();
			person1.setSubject(p1);
			person1.setFamilyName("test1");
			person1.addGivenName("test1");
			person1.addEmail("test1@dataone.org");
                    
			Subject certP1 = new Subject();
                        String standardizedPrimarySubject = CertificateManager.getInstance().standardizeDN(primarySubject);
			certP1.setValue(standardizedPrimarySubject);

			Subject p2 = new Subject();
			p2.setValue(secondarySubjectNonStandard);
			Person person2 = new Person();
			person2.setSubject(p2);
			person2.setFamilyName("test2");
			person2.addGivenName("test2");
			person2.addEmail("test2@dataone.org");

			CNIdentityLDAPImpl identityService = new CNIdentityLDAPImpl();
//			identityService.setServer(server);
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
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentityRequest", p1.getValue());
			assertTrue(check);
			// request is one-way
//			check = identityService.checkAttribute(p1.getValue(), "equivalentIdentityRequest", p2.getValue());
//			assertFalse(check);
			// not yet confirmed on either end
			check = ldapTestIdentityCleanup.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertFalse(check);
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertFalse(check);
			// accept request
			check = identityService.confirmMapIdentity(getSession(p2), p1);
			assertTrue(check);

			// double check reciprocal mapping
			check = ldapTestIdentityCleanup.checkAttribute(p1.getValue(), "equivalentIdentity", p2.getValue());
			assertTrue(check);
			check = ldapTestIdentityCleanup.checkAttribute(p2.getValue(), "equivalentIdentity", p1.getValue());
			assertTrue(check);

                        // find out if this will fail due to recursive bug?
                        SubjectInfo subjectInfo = identityService.getSubjectInfo(getSession(certP1), certP1);
			assertNotNull(subjectInfo);

                        
			// clean up (this is not required for service to be functioning)
			check = ldapTestIdentityCleanup.removeSubject(p1);
			assertTrue(check);
			check = ldapTestIdentityCleanup.removeSubject(p2);
			assertTrue(check);
                        nodeRegistryService.deleteNode(cnNodeReference);
                        
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
}

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


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.util.Set;

import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.client.v2.itk.D1Client;
import org.dataone.configuration.Settings;
import org.dataone.service.cn.impl.v2.ReserveIdentifierService;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.ObjectList;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.Member;

/**
 *	Tests the LDAP implementation for reserving Identifiers on the CN
 *
 * @author leinfelder
 */
public class ReserveIdentifierServiceTest {

    public static Log log = LogFactory.getLog(ReserveIdentifierServiceTest.class);

	// use Configuration to look up testing values
	//private String server = Settings.getConfiguration().getString("test.ldap.server.1");

	private String primarySubject = Settings.getConfiguration().getString("test.primarySubject");
	private String secondarySubject = Settings.getConfiguration().getString("test.secondarySubject");
	private String orcidSubject = Settings.getConfiguration().getString("test.orcidSubject");


	private static Session getSession(Subject subject) {
		Session session = new Session();
		session.setSubject(subject);
		return session;
	}

    @Before
    public void setUp() throws Exception {
        
        // Hazelcast Config testing

        ClasspathXmlConfig hzConfig = new ClasspathXmlConfig("org/dataone/configuration/hazelcast.xml");

        System.out.println("Hazelcast Group Config:\n" + hzConfig.getGroupConfig());
        System.out.print("Hazelcast Maps: ");
        for (String mapName : hzConfig.getMapConfigs().keySet()) {
            System.out.print(mapName + " ");
        }
        System.out.println();
        System.out.print("Hazelcast Queues: ");
        for (String queueName : hzConfig.getQConfigs().keySet()) {
            System.out.print(queueName + " ");
        }
        System.out.println();
        HazelcastInstance hzMember = Hazelcast.init(hzConfig);
        Set<Member> members = hzMember.getCluster().getMembers();
        System.out.println("Cluster size " + members.size());
        for (Member m : members) {
            System.out.println(hzMember.getName() + "'s InetSocketAddress: "
                    + m.getInetSocketAddress());
        }

    }
    
    @After
    public void tearDown() throws Exception {
        Hazelcast.shutdownAll();
    }
    
	@Test
	public void reserveIdentifier()  {

		try {

			ReserveIdentifierService service = new ReserveIdentifierService();

			// subject
			Subject subject = new Subject();
			subject.setValue(primarySubject);

			// another subject
			Subject anotherSubject = new Subject();
			anotherSubject.setValue(secondarySubject);

			// identifier
			Identifier pid = new Identifier();
			pid.setValue("test");

			boolean check = false;

			Identifier retPid = null;
			//service.setServer(server);
			retPid = service.reserveIdentifier(getSession(subject), pid);
			assertNotNull(retPid);

			// make sure that we get an error when attempting to reserve as  someone else
			try {
				retPid = service.reserveIdentifier(getSession(anotherSubject), pid);
			} catch (NotAuthorized na) {
				retPid = null;
			}
			assertNull(retPid);

			// check that he still have the reservation
			check = service.hasReservation(getSession(subject), subject, pid);
			assertTrue(check);

			// now clean up
			check = service.removeReservation(getSession(subject),  pid);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void reserveIdentifierOrcid()  {

		try {

			ReserveIdentifierService service = new ReserveIdentifierService();

			// subject
			Subject subject = new Subject();
			subject.setValue(orcidSubject);

			// another subject
			Subject anotherSubject = new Subject();
			anotherSubject.setValue(secondarySubject);

			// identifier
			Identifier pid = new Identifier();
			pid.setValue("testOrcid");

			boolean check = false;

			Identifier retPid = null;
			//service.setServer(server);
			retPid = service.reserveIdentifier(getSession(subject), pid);
			assertNotNull(retPid);

			// make sure that we get an error when attempting to reserve as  someone else
			try {
				retPid = service.reserveIdentifier(getSession(anotherSubject), pid);
			} catch (NotAuthorized na) {
				retPid = null;
			}
			assertNull(retPid);

			// check that he still have the reservation
			check = service.hasReservation(getSession(subject), subject, pid);
			assertTrue(check);

			// now clean up
			check = service.removeReservation(getSession(subject),  pid);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void reserveIdentifierOrcidReverse()  {

		try {

			ReserveIdentifierService service = new ReserveIdentifierService();

			// subject
			Subject subject = new Subject();
			subject.setValue(primarySubject);

			// another subject
			Subject anotherSubject = new Subject();
			anotherSubject.setValue(orcidSubject);

			// identifier
			Identifier pid = new Identifier();
			pid.setValue("testOrcidReverse");

			boolean check = false;

			Identifier retPid = null;
			//service.setServer(server);
			retPid = service.reserveIdentifier(getSession(subject), pid);
			assertNotNull(retPid);

			// make sure that we get an error when attempting to reserve as  someone else
			try {
				retPid = service.reserveIdentifier(getSession(anotherSubject), pid);
			} catch (NotAuthorized na) {
				retPid = null;
			}
			assertNull(retPid);

			// check that he still have the reservation
			check = service.hasReservation(getSession(subject), subject, pid);
			assertTrue(check);

			// now clean up
			check = service.removeReservation(getSession(subject),  pid);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}
	
	@Test
	public void reserveIdentifier_exists()  {

		try {

			ReserveIdentifierService service = new ReserveIdentifierService();

			// subject
			Subject subject = new Subject();
			subject.setValue(primarySubject);

			// another subject
			Subject anotherSubject = new Subject();
			anotherSubject.setValue(secondarySubject);

			// find existing identifier
			Identifier sid = null;
			
			// find a SID if we can
			InputStream is = D1Client.getCN().query(null, "solr", "?q=seriesId:*&fl=seriesId");
			Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
			String seriesId = XPathFactory.newInstance().newXPath().evaluate("/response/result/doc/str", document);
			if (seriesId != null) {
				sid = new Identifier();
				sid.setValue(seriesId);
			}
			
			if (sid == null) {
				// fallback to pid-based test, not as thorough
				fail("NEED SID FOR THIS TEST");
				log.warn("Could not find suitable SID for testing, looking up PID");
				ObjectList ol = D1Client.getCN().listObjects(null, null, null, null, null, null, 0, 10);
				if (ol != null && ol.sizeObjectInfoList() > 0) {
					sid = ol.getObjectInfo(0).getIdentifier();
				}
			}	
			assertNotNull(sid);
			
			Identifier retPid = null;
			//service.setServer(server);
			try {
				retPid = service.reserveIdentifier(getSession(subject), sid);
			} catch (IdentifierNotUnique inu) {
				// this is expected
				return;
			}
			fail("exception should be thrown and reservation should not be accepted for existing id: " + sid.getValue());

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

	@Test
	public void expire()  {
		ReserveIdentifierService service = new ReserveIdentifierService();
		//service.setServer(server);
		try {
			service.expireEntries(0);
		} catch (NamingException e) {
			e.printStackTrace();
			fail();
		}
	}

    @Test
    public void generateIdentifier()  {

        try {

            ReserveIdentifierService service = new ReserveIdentifierService();

            // subject
            Subject subject = new Subject();
            subject.setValue(primarySubject);

            // another subject
            Subject anotherSubject = new Subject();
            anotherSubject.setValue(secondarySubject);

            // identifier
            Identifier pid = new Identifier();
            pid.setValue("test");

            boolean check = false;

            Identifier retPid = null;
            //service.setServer(server);
            retPid = service.generateIdentifier(getSession(subject), "UUID", null);
            log.debug("Generated PID: " + retPid.getValue());
            assertNotNull(retPid);
            assertTrue(retPid.getValue().startsWith("urn:uuid:"));

            // check that he still have the reservation
            check = service.hasReservation(getSession(subject), subject, retPid);
            assertTrue(check);

            // now clean up
            check = service.removeReservation(getSession(subject), retPid);
            assertTrue(check);

        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

    }
    
    @Test
    public void generateIdentifierOrcid()  {

        try {

            ReserveIdentifierService service = new ReserveIdentifierService();

            // subject
            Subject subject = new Subject();
            subject.setValue(orcidSubject);

            // another subject
            Subject anotherSubject = new Subject();
            anotherSubject.setValue(secondarySubject);

            // identifier
            Identifier pid = new Identifier();
            pid.setValue("test");

            boolean check = false;

            Identifier retPid = null;
            //service.setServer(server);
            retPid = service.generateIdentifier(getSession(subject), "UUID", null);
            log.debug("Generated PID: " + retPid.getValue());
            assertNotNull(retPid);
            assertTrue(retPid.getValue().startsWith("urn:uuid:"));

            // check that he still have the reservation
            check = service.hasReservation(getSession(subject), subject, retPid);
            assertTrue(check);

            // now clean up
            check = service.removeReservation(getSession(subject), retPid);
            assertTrue(check);

        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

    }

}

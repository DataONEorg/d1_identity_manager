package org.dataone.service.cn.impl.v1;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Set;

import javax.naming.NamingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

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
	private String server = Settings.getConfiguration().getString("test.ldap.server.1");
	private String serverReplica = Settings.getConfiguration().getString("test.ldap.server.1");
	private int replicationDelay = Settings.getConfiguration().getInt("test.replicationDelay"); // milliseconds
	private int replicationAttempts = Settings.getConfiguration().getInt("test.replicationAttempts");

	private String primarySubject = Settings.getConfiguration().getString("test.primarySubject");
	private String secondarySubject = Settings.getConfiguration().getString("test.secondarySubject");

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
			service.setServer(server);
			retPid = service.reserveIdentifier(getSession(subject), pid);
			assertNotNull(retPid);

			// make sure that we get an error when attempting to reserve as  someone else
			try {
				retPid = service.reserveIdentifier(getSession(anotherSubject), pid);
			} catch (IdentifierNotUnique inu) {
				retPid = null;
			}
			assertNull(retPid);

			// check that he still have the reservation
			check = service.hasReservation(getSession(subject), pid);
			assertTrue(check);

			// now clean up
			check = service.removeReservation(getSession(subject), pid);
			assertTrue(check);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

	@Test
	public void expire()  {
		ReserveIdentifierService service = new ReserveIdentifierService();
		service.setServer(server);
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
            service.setServer(server);
            retPid = service.generateIdentifier(getSession(subject), "UUID", null);
            log.debug("Generated PID: " + retPid.getValue());
            assertNotNull(retPid);
            assertTrue(retPid.getValue().startsWith("urn:uuid:"));

            // check that he still have the reservation
            check = service.hasReservation(getSession(subject), retPid);
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

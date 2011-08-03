package org.dataone.service.cn.impl.v1;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.naming.NamingException;

import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.junit.Test;

/**
 *	Tests the LDAP implementation for reserving Identifiers on the CN
 *
 * @author leinfelder
 */
public class ReserveIdentifierServiceTest {

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


}

package org.dataone.service.cn;


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.dataone.configuration.Settings;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.types.Identifier;
import org.dataone.service.types.Session;
import org.dataone.service.types.Subject;
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
			retPid = service.reserveIdentifier(getSession(subject), pid, null, null);
			assertNotNull(retPid);
			
			// make sure that we get an error when attempting to reserve as  someone else
			try {
				retPid = service.reserveIdentifier(getSession(anotherSubject), pid, null, null);
			} catch (IdentifierNotUnique inu) {
				retPid = null;
			}
			assertNull(retPid);
			
			// now clean up
//			check = service.removeReservation(getSession(subject), pid);
//			assertTrue(check);
	
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	
	}
	
	@Test
	public void expire()  {
		ReserveIdentifierService service = new ReserveIdentifierService();
		service.setServer(server);
		service.expireEntries(0);
	}
	
	
}

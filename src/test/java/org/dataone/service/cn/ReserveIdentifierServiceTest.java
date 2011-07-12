package org.dataone.service.cn;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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

			ReserveIdentifierService service = new ReserveIdentifierService();
			service.setServer(server);
			check = service.reserveIdentifier(getSession(subject), pid);
			assertTrue(check);
			
			// make sure that we get an error when attempting to reserve as  someone else
			try {
				check = service.reserveIdentifier(getSession(anotherSubject), pid);
			} catch (IdentifierNotUnique inu) {
				check = false;
			}
			assertFalse(check);
			
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

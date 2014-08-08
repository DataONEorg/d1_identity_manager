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

package org.dataone.service.cn.impl.v1;

import javax.naming.NamingException;

import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;

/**
 * Class used for adding and managing reserved Identifiers
 * Identifiers are housed in LDAP and replicated across CNs
 *
 * @author leinfelder
 *
 */
public class ReserveIdentifierService {

	private org.dataone.service.cn.impl.v2.ReserveIdentifierService impl = null;

	public ReserveIdentifierService() {
		this.impl = new org.dataone.service.cn.impl.v2.ReserveIdentifierService();
	}
	
	public String getBase() {
	    return impl.getBase();
	}
	
	public void setBase(String base) {
	    impl.setBase(base);
	}
	
	public String getServer() {
	    return impl.getServer();
	}
	
	public void setServer(String server) {
	    impl.setServer(server);
	}
	
	public String getAdmin() {
        return impl.getAdmin();
    }

    public void setAdmin(String admin) {
        impl.setAdmin(admin);
    }
    
    public String getPassword() {
        return impl.getPassword();
    }

    public void setPassword(String password) {
        impl.setPassword(password);
    }
	
	public void expireEntries(int numberOfDays) throws NamingException {
		impl.expireEntries(numberOfDays);
	}
	
	/**
	 * Reserves the given Identifier for the Subject in the Session
	 * Checks ownership of the pid by the subject if it already exists
	 * TODO: update created date in cases where we are "re-reserving"?
	 * @param session
	 * @param pid
	 * @return
	 * @throws IdentifierNotUnique
	 * @throws NotAuthorized 
	 */
	public Identifier reserveIdentifier(Session session, Identifier pid) throws IdentifierNotUnique, NotAuthorized {

		return impl.reserveIdentifier(session, pid);
	}

	/**
	 * Generate a unique identifier and reserve it for use by Subject in the Session.  The identifier
	 * is generated according to the rules of the provided scheme, which must be a scheme which
	 * is support by the generateIdentifier service.  Currently, the only supported scheme is
	 * "UUID" identifiers.
	 * 
	 * @param session the Session identifying the caller
	 * @param scheme the name of the identifier scheme to be used in generating IDs
	 * @param fragment a string fragment that should be included in the identifier (optional)
	 * @return the Identifier that was generated
	 * @throws InvalidRequest if the scheme is not supported, or no scheme is provided
	 * @throws NotAuthorized 
	 */
	public Identifier generateIdentifier(Session session, String scheme, String fragment) throws InvalidRequest, ServiceFailure, NotAuthorized {

	    return impl.generateIdentifier(session, scheme, fragment);
	}

	/**
	 *
	 * @param session
	 * @param pid
	 * @return
	 * @throws NotAuthorized
	 * @throws NotFound
	 * @throws IdentifierNotUnique 
	 */
	public boolean removeReservation(Session session, Identifier pid) throws NotAuthorized, NotFound, IdentifierNotUnique {

		return impl.removeReservation(session, pid);
	}

	public boolean hasReservation(Session session, Subject subject, Identifier pid) throws NotAuthorized, NotFound, IdentifierNotUnique {
		return impl.hasReservation(session, subject, pid);
	}

}

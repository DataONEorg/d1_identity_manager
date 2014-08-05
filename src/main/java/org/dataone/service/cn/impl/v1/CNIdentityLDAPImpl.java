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

import org.dataone.service.cn.v1.CNIdentity;
import org.dataone.service.exceptions.IdentifierNotUnique;
import org.dataone.service.exceptions.InvalidCredentials;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Group;
import org.dataone.service.types.v1.Person;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.SubjectInfo;

/**
 * Proposed LDAP schema extensions
 *
 * objectClass: d1Principal
 * attributes:
 * 		equivalentIdentity (0...n) - used when mapping is confirmed
 * 		equivalentIdentityRequest (0...n) - used when mapping is requested (before confirmation)
 * 		isVerified (1...1) - used when untrusted account is registered
 *
 * objectClass: d1Group
 * attributes:
 * 		adminIdentity (0...n) - references other Principals that are allowed to modify the group
 *
 * @author leinfelder
 *
 */
public class CNIdentityLDAPImpl implements CNIdentity {

	private org.dataone.service.cn.impl.v2.CNIdentityLDAPImpl impl = null;
	
	public CNIdentityLDAPImpl() {
		this.impl = new org.dataone.service.cn.impl.v2.CNIdentityLDAPImpl();
	}
	
	public void setServer(String server) {
		impl.setServer(server);
	}
	
	public String getServer() {
        return impl.getServer();
    }
	
    public void setBase(String base) {
        impl.setBase(base);
    }
    
    public String getBase() {
        return impl.getBase();
    }
    
    public boolean checkAttribute(String dn, String attributeName, String attributeValue) {
    	return impl.checkAttribute(dn, attributeName, attributeValue);
    }
    
    public boolean removeEntry(String dn) {
    	return impl.removeEntry(dn);
    }
        
    @Override    
	public Subject createGroup(Session session, Group group) throws ServiceFailure,
			InvalidToken, NotAuthorized, NotImplemented,
			IdentifierNotUnique, InvalidRequest {

    	return impl.createGroup(session, group);
	}

	@Override
    public boolean updateGroup(Session session, Group group)
    	throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {

		return impl.updateGroup(session, group);

    }
	
	@Override
	public boolean mapIdentity(Session session, Subject primarySubject, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

        return impl.mapIdentity(session, primarySubject, secondarySubject);
	}
    
	@Override
	public boolean requestMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented, InvalidRequest {

		return impl.requestMapIdentity(session, secondarySubject);
	}

	@Override
	public boolean confirmMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {

		return impl.confirmMapIdentity(session, secondarySubject);
	}

	@Override
	public Subject updateAccount(Session session, Person p) throws ServiceFailure,
		InvalidCredentials, NotImplemented, InvalidRequest, NotAuthorized {

		return impl.updateAccount(session, p);
	}

	@Override
	public boolean verifyAccount(Session session, Subject subject) throws ServiceFailure,
			NotAuthorized, NotImplemented, InvalidToken, InvalidRequest {
		
		return impl.verifyAccount(session, subject);
	}

	@Override
	public Subject registerAccount(Session session, Person p) throws ServiceFailure, IdentifierNotUnique, InvalidCredentials,
    NotImplemented, InvalidRequest {
	   return impl.registerAccount(session, p);
	}

	@Override
	public SubjectInfo getSubjectInfo(Session session, Subject subject)
    	throws ServiceFailure, NotAuthorized, NotImplemented, NotFound {
		return impl.getSubjectInfo(session, subject);
	}
	
	@Override
	public SubjectInfo listSubjects(Session session, String query, String status, Integer start,
	        Integer count) throws ServiceFailure, InvalidToken, NotAuthorized,
	        NotImplemented {

		return impl.listSubjects(session, query, status, start, count);
	}
	

	public boolean removeSubject(Subject p) {
		return impl.removeSubject(p);
	}
	
	@Override
	public boolean denyMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {
		return impl.denyMapIdentity(session, secondarySubject);
	}
	
	@Override
	public SubjectInfo getPendingMapIdentity(Session session, Subject subject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {
		
		return impl.getPendingMapIdentity(session, subject);
		
	}
	
	@Override
	public boolean removeMapIdentity(Session session, Subject secondarySubject)
			throws ServiceFailure, InvalidToken, NotAuthorized, NotFound,
			NotImplemented {
		return impl.removeMapIdentity(session, secondarySubject);
	}
	
	@Override
    public Subject registerAccount(Person person) throws ServiceFailure, NotAuthorized, IdentifierNotUnique, InvalidCredentials, NotImplemented, InvalidRequest, InvalidToken {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Subject updateAccount(Person person) throws ServiceFailure, NotAuthorized, InvalidCredentials, NotImplemented, InvalidRequest, InvalidToken, NotFound {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean verifyAccount(Subject subject) throws ServiceFailure, NotAuthorized, NotImplemented, InvalidToken, InvalidRequest, NotFound {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SubjectInfo getSubjectInfo(Subject subject) throws ServiceFailure, NotAuthorized, NotImplemented, NotFound, InvalidToken {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SubjectInfo listSubjects(String query, String status, Integer start, Integer count) throws InvalidRequest, ServiceFailure, InvalidToken, NotAuthorized, NotImplemented {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean mapIdentity(Subject primarySubject, Subject secondarySubject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest, IdentifierNotUnique {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean requestMapIdentity(Subject subject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest, IdentifierNotUnique {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean confirmMapIdentity(Subject subject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SubjectInfo getPendingMapIdentity(Subject subject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean denyMapIdentity(Subject subject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeMapIdentity(Subject subject) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Subject createGroup(Group group) throws ServiceFailure, InvalidToken, NotAuthorized, NotImplemented, IdentifierNotUnique {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean updateGroup(Group group) throws ServiceFailure, InvalidToken, NotAuthorized, NotFound, NotImplemented, InvalidRequest {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.dataone.service.cn.impl.v2;


import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateAuthenticator;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.authn.SimpleAuthenticator;

import org.dataone.test.apache.directory.server.integ.ApacheDSSuiteRunner;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 *
 * @author waltz
 */

@RunWith(ApacheDSSuiteRunner.class)
@Suite.SuiteClasses({ CNIdentityLDAPImplTestUnit.class })
@CreateDS(allowAnonAccess = false, enableAccessControl=true,  authenticators ={@CreateAuthenticator(type = SimpleAuthenticator.class)} ,name = "org", partitions = { @CreatePartition(name = "org", suffix = "dc=org") })
@ApplyLdifFiles({"org/dataone/test/apache/directory/server/dataone-schema.ldif", "org/dataone/test/apache/directory/server/dataone-base-data.ldif", "org/dataone/test/services/types/v1/nodes/ldif/devNodeList.ldif", "org/dataone/test/services/types/v1/person/ldif/devTestPrincipal.ldif", "org/dataone/resources/samples/v2/ldif/identityTestCN.ldif"})
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port=15389) })
public class IdentityManagerSuiteTest {


}
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */




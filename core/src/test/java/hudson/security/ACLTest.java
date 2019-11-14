package hudson.security;

import javax.annotation.Nonnull;

import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.junit.Assert;
import org.junit.Test;

import jenkins.model.Jenkins;

public class ACLTest {

    Authentication adminUser = new UsernamePasswordAuthenticationToken("admin","admin");
    Authentication configUSer = new UsernamePasswordAuthenticationToken("config","config");
    Authentication readUser = new UsernamePasswordAuthenticationToken("read","read");
    DummyACL dummyACL = new DummyACL();

    @Test
    public void userWithPermissionShouldBeOk() {

        DummyACL.as(adminUser);
        dummyACL.checkPermission(Jenkins.ADMINISTER);

        DummyACL.as(configUSer);
        dummyACL.checkPermission(Jenkins.CONFIGURE_JENKINS);

        DummyACL.as(readUser);
        dummyACL.checkPermission(Jenkins.READ);

    }

    @Test
    public void userWithoutPermissionShouldRaiseException() {

        try {
            DummyACL.as(Jenkins.ANONYMOUS);
            dummyACL.checkPermission(Jenkins.ADMINISTER);
            Assert.fail("An AccessDeniedException2 should be raised.");

        } catch (AccessDeniedException2 e){
            //We want that to happen
        }

    }

    @Test
    public void userWithOneRequiredPermissionShouldBeOk(){
        DummyACL.as(adminUser);
        dummyACL.checkHasAtLeastOnePermission(Jenkins.ADMINISTER, Jenkins.CONFIGURE_JENKINS);
    }

    @Test
    public void userWithoutRequiredPermissionShouldThrowsException(){
        try {
            DummyACL.as(readUser);
            dummyACL.checkHasAtLeastOnePermission(Jenkins.ADMINISTER, Jenkins.CONFIGURE_JENKINS);
            Assert.fail("An AccessDeniedException2 should be raised.");
        } catch (AccessDeniedException2 e){
            //We want that to happen
        }
    }

    /**
     * Dummy ACL, one user per permission.
     */
    class DummyACL extends ACL {

        @Override
        public boolean hasPermission(@Nonnull Authentication a, @Nonnull Permission permission) {
            return (a.getName().equals("admin") && Jenkins.ADMINISTER.equals(permission))
                   || (a.getName().equals("config") && Jenkins.CONFIGURE_JENKINS.equals(permission))
                   || (a.getName().equals("read") && Jenkins.READ.equals(permission)) ;
        }
    }

}



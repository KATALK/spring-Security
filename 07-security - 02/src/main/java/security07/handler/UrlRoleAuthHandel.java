package security07.handler;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @Author EdiMen
 * @Data 2020/10/11--20:44
 * @Version 1.0
 */

/**
 * 角色 权限 路由处理
 */
public class UrlRoleAuthHandel implements AccessDecisionVoter<Object> {
    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        if (null == configAttribute.getAttribute()){
            return false;
        }
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }


    /**
     * ACCESS_GRANTED – 同意
     * ACCESS_DENIED – 拒绝
     * ACCESS_ABSTAIN – 弃权
     */
    @Override
    public int vote(Authentication authentication, Object o, Collection<ConfigAttribute> collection) {
        if (null==authentication){
            return ACCESS_DENIED;
        }
        int result = ACCESS_ABSTAIN;
        Collection<? extends GrantedAuthority> userRoles = authentication.getAuthorities();
       for (ConfigAttribute urlRole: collection){
           if (this.supports(urlRole)){
               result = ACCESS_ABSTAIN;
               for (GrantedAuthority userRole : userRoles){
                   if (urlRole.getAttribute().equals(userRole.getAuthority())){
                       return ACCESS_GRANTED;
                   }
               }
           }
       }
        return result;
    }
}

package security07.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Service;
import security07.mapper.SysMenuMapper;

import java.util.Collection;
import java.util.List;

/**路由动态获取角色
 * @Author EdiMen
 * @Data 2020/10/11--20:12
 * @Version 1.0
 */
@Service
public class UrlRolesFilterHandler implements FilterInvocationSecurityMetadataSource {

    @Autowired(required = false)
    private SysMenuMapper sysMenuMapper;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        String requestUrl = ((FilterInvocation) object).getRequestUrl();
        List<String> roleNames = sysMenuMapper.selectRoleNamesByUrl(requestUrl);
        String[] names = new String[roleNames.size()];
        for (int i = 0;i < roleNames.size();i++){
            names[i] = roleNames.get(i);
        }
        return SecurityConfig.createList(names);
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}

package security07.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * @Author EdiMen
 * @Data 2020/10/11--20:27
 * @Version 1.0
 */
public class DefindeObjectPostProcessor implements ObjectPostProcessor<FilterSecurityInterceptor> {

    @Autowired
    private UrlRolesFilterHandler urlRolesFilterHandler;
    @Override
    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
        object.setSecurityMetadataSource(urlRolesFilterHandler);
        return object;
    }
}

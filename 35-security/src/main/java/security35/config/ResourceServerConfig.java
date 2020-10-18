package security35.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Bean
    @LoadBalanced
    public RestTemplate restTemplate(RestTemplateBuilder builder){
        return builder.build();
    }

    @Autowired
    private RestTemplate restTemplate;


    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(new JwtTokenStore(accessTokenConverter())).stateless(true);

        /* 配置令牌验证 */
        RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        remoteTokenServices.setAccessTokenConverter(accessTokenConverter());
        remoteTokenServices.setRestTemplate(restTemplate);

        remoteTokenServices.setCheckTokenEndpointUrl("http://34-security/oauth/check_token");

        remoteTokenServices.setClientId("clientId");
        remoteTokenServices.setClientSecret("secret");

        resources.tokenServices(remoteTokenServices).stateless(true);
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("secret");
        return converter;
    }



    /* 配置资源拦截规则 */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        // /save/no不受保护
        // /user/save 受保护
        http.authorizeRequests()
                .antMatchers("/save/**").permitAll()
                .anyRequest().authenticated();

        http.exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler());
    }


}
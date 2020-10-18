package security34.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Order(2147483636)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* 跨域伪造请求限制=无效 */
        http.csrf().disable();

        /* 开启授权认证 */
        http.authorizeRequests()
                .antMatchers("/oauth/*").permitAll()
                .anyRequest().authenticated();

        /* 登录配置 */
        http.formLogin().permitAll();

        /* session 设置为 IF_REQUIRED 有需要才生成 */
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.parentAuthenticationManager(authenticationManagerBean());
        auth.inMemoryAuthentication()
            .passwordEncoder(passwordEncoder())
            .withUser("admin")
            .password(new BCryptPasswordEncoder().encode("admin"))
            .roles("USER");
    }



    /** 授权服务配置需要用到这个 bean  */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /** 配置密码加密*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

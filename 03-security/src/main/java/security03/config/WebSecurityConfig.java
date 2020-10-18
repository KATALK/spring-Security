package security03.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 关闭csrf
        http.csrf().disable();

        // 配置登录页面
        http.formLogin().loginPage("/login").permitAll();

        // 配置登录成功后的默认页面
        http.formLogin().defaultSuccessUrl("/home");

        // 登出授权
        http.logout().permitAll();

        // 授权配置
        http.authorizeRequests().anyRequest().fullyAuthenticated();
    }

}


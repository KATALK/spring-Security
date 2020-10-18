package security07.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import security07.handler.*;
import security07.mapper.SysUserMapper;
import security07.model.SysUser;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    RememberMeHandler rememberMeHandler;
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 关闭csrf
        http.csrf().disable();

        // 配置登录页面
        http.formLogin().loginPage("/login").permitAll();

        // 配置登录成功后的操作
        http.formLogin().successHandler(new LoginSuccessHandler());

        // 用户权限不足处理器
        http.exceptionHandling().accessDeniedHandler(new AuthLimitHandler());

        // 登出授权
        http.logout().permitAll();

        // 授权配置
        http.authorizeRequests()
                /* 所有静态文件可以访问 */
                .antMatchers("/js/**","/css/**","/images/**").permitAll()
                /* 所有 以/ad 开头的 广告页面可以访问 */
                .antMatchers("/ad/**").permitAll()
                /*动态url权限*/
                .withObjectPostProcessor(new DefindeObjectPostProcessor())
                /*url决策管理*/
                .accessDecisionManager(accessDecisionManager())
                .anyRequest().authenticated();
                http.rememberMe()
                        .tokenRepository(rememberMeHandler)
                        .tokenValiditySeconds(60*60*24)
                        .userDetailsService(userDetailsService());
    }


//    @Bean
//    public JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
//        jdbcUserDetailsManager.setDataSource(dataSource);
//        return jdbcUserDetailsManager;
//    }


    @Autowired(required = false)
    private SysUserMapper sysUserMapper;

    @Override
    protected UserDetailsService userDetailsService() {
        return username->{
            if (username==null || username.trim().length()<=0){
                throw new UsernameNotFoundException("用户名为空");
            }
            SysUser sysUser = sysUserMapper.selectByUserName(username);
            if (sysUser !=null){
                return sysUser;
            }
            throw new UsernameNotFoundException("用户不存在");
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
    }

    /**
     * AffirmativeBased – 任何一个AccessDecisionVoter返回同意则允许访问
     * ConsensusBased – 同意投票多于拒绝投票（忽略弃权回答）则允许访问
     * UnanimousBased – 每个投票者选择弃权或同意则允许访问
     *
     * 决策管理
     */
    private AccessDecisionManager accessDecisionManager(){
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new AuthenticatedVoter());
        decisionVoters.add(new RoleVoter());
        /*路由权限管理*/
        decisionVoters.add(new UrlRoleAuthHandel());
        return new UnanimousBased(decisionVoters);
    }
}


package com.mciws.uaa.config;

import com.mciws.uaa.config.security.MciActiveDirectoryLdapAuthenticationProvider;
import com.mciws.uaa.config.security.MciFilterBasedLdapUserSearch;
import com.mciws.uaa.config.security.PlainTextPasswordEncoder;
import com.mciws.uaa.filter.JwtRequestFilter;
import com.mciws.uaa.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtRequestFilter jwtRequestFilter;
    private final LdapContextSource ldapContextSource;
    private final LoginAttemptService loginAttemptService;

    @Autowired
    public SecurityConfiguration(JwtRequestFilter jwtRequestFilter, LdapContextSource ldapContextSource, LoginAttemptService loginAttemptService) {
        this.jwtRequestFilter = jwtRequestFilter;
        this.ldapContextSource = ldapContextSource;
        this.loginAttemptService = loginAttemptService;
    }


    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(activeDirectoryLdapAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()
                .authorizeRequests().antMatchers("/login","/user_info").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    @Primary
    @Override
    public UserDetailsService userDetailsService() {
        return new LdapUserDetailsService(new MciFilterBasedLdapUserSearch(ldapContextSource));
    }

    @Bean
    public AuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
        MciActiveDirectoryLdapAuthenticationProvider authenticationProvider =
                new MciActiveDirectoryLdapAuthenticationProvider(ldapContextSource, passwordEncoder(), loginAttemptService);
        authenticationProvider.setConvertSubErrorCodesToExceptions(true);
        authenticationProvider.setUseAuthenticationRequestCredentials(true);
        return authenticationProvider;
    }


    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PlainTextPasswordEncoder();
    }

}

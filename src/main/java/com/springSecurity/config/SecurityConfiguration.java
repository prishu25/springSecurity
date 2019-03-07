package com.springSecurity.config;

import net.bytebuddy.implementation.bind.MethodDelegationBinder;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
                .withUser("ajay").password("{noop}test").roles("USER").and()
                .withUser("demo").password("{noop}test2").roles("ADMIN");
        System.out.println("==============First ==================");


}


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception
    {
        /**
         * basic authentication that allow all the request
         */
//        httpSecurity.authorizeRequests()
//                    .anyRequest()
//                    .permitAll()
//                    .and()
//                    .httpBasic();
        /**
         * When we have to give access based on Username and Password
         */
//        httpSecurity.authorizeRequests()
//                .anyRequest()
//                .fullyAuthenticated()
//                .and()
//                .httpBasic();

        /**
         * except hello all other request should be authenticated however only hello request should authenticated and authorized using the role "USER"
         * NOt Working we can also do using annotation in Rest controller
         */
        httpSecurity.authorizeRequests()
                .antMatchers("**/hello").hasRole("USER")
                .anyRequest()
                .fullyAuthenticated()
                .and()
                .httpBasic();




        httpSecurity.csrf().disable();
        System.out.println("==============second ==================");
    }
}

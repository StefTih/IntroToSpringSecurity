package com.example.introtospringsecurity.security;

import com.example.introtospringsecurity.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.introtospringsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //This enables the Authentication annotations used in the controller
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    //    This is the configuration which says that we have to:
//    1. Authorise any requests
//    2. The client must specify the username and password
//    3. The mechanism that we want to enforce the authenticity of the client is by using the basic authentication
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                This is setting up the repository, so how the tokens are actually generated. If you want to submit
//                forms from any client aka Angular you need to enable csrfTokens.
//                TODO: You need to learn more on this topic
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                //That way you specify that this can only be accessed by students
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // Authority is pretty much the same as permission
//                The order that we add the matchers matter! Therefore in order to rely on order we can
//                use annotations on the controller methods which will decide which roles have access to which methods!
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
//                .httpBasic();
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses",true)
                    .passwordParameter("password") //optional*, used to change the name of the HTML input
                    .usernameParameter("username") //optional*, used to change the name of the HTML input
                .and()
                // defaults is 2 weeks, but this is how you can extend your session using Remember Me
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("secureKey")
                    .rememberMeParameter("remember-me") //optional*, used to change the name of the HTML input
                .and()
                .logout()
                    .logoutUrl("/logout")
                //If you use csrf you want to delete this line because you will be using POST instead of GET
                //What this line is really doing is that whenever you go to the specific URl with the httpMethod - LOGOUT!
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me")
                    .logoutSuccessUrl("/login"); //After you have successuly logged out you can go to /login
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder); //Allows passwords to be decoded
        provider.setUserDetailsService(applicationUserService);
        return provider;

    }


////    This is how you retrieve your users from your database!
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails donRobbie = User.builder()
//                .username("Don")
//                .password(passwordEncoder.encode("Robbie"))
////                .roles(STUDENT.name()) // ROLE_STUDENT Inside the roles you get the name of the role
//                //This is how you can assign authorities to the different users
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails troopz = User.builder()
//                .username("Troopz")
//                .password(passwordEncoder.encode("Auba"))
////                .roles(ADMIN.name()) // ROLE_ADMIN NOTE: You can assign more than one role to a user!
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails dt = User.builder()
//                .username("DT")
//                .password(passwordEncoder.encode("Behave"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE NOTE: You can assign more than one role to a user!
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                donRobbie,
//                troopz,
//                dt
//        );
//
//    }
}

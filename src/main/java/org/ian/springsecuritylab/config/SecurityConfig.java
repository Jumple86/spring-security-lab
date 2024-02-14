package org.ian.springsecuritylab.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.ian.springsecuritylab.dao.UserDao;
import org.ian.springsecuritylab.filter.LoginFilter;
import org.ian.springsecuritylab.filter.VerificationCodeFilter;
import org.ian.springsecuritylab.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Configuration
//@EnableWebSecurity
@Log4j2
public class SecurityConfig {
//    private final VerificationCodeFilter verificationCodeFilter;

//    public SecurityConfig(VerificationCodeFilter verificationCodeFilter) {
//        this.verificationCodeFilter = verificationCodeFilter;
//    }

    @Bean
    public UserDetailsService userDetailsService(UserDao userDao) {
        UserDetails user = User.withUsername("user")
                .password("123")
                .roles("USER")
                .build();
        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
        inMemoryUserDetailsManager.createUser(user);
//        return inMemoryUserDetailsManager;

        return new UserService(userDao);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public LoginFilter loginFilter(AuthenticationManager authenticationManager) throws Exception {
        LoginFilter loginFilter = new LoginFilter();
        loginFilter.setFilterProcessesUrl("/doLogin");
        loginFilter.setAuthenticationManager(authenticationManager);
        loginFilter.setSecurityContextRepository(new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository()
        ));
        loginFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            Object principal = authentication.getPrincipal();
            response.setContentType("application/json; charset=utf-8");
            PrintWriter printWriter = response.getWriter();
            Map<String, Object> responseMap = Map.of("principal", principal, "details", authentication.getDetails());
            printWriter.write(new ObjectMapper().writeValueAsString(responseMap));
            printWriter.flush();
            printWriter.close();
        });
        loginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
            response.setContentType("application/json; charset=utf-8");
            PrintWriter printWriter = response.getWriter();
            printWriter.write(exception.toString());
            printWriter.flush();
            printWriter.close();
        });

        ConcurrentSessionControlAuthenticationStrategy strategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
        strategy.setMaximumSessions(1);
        loginFilter.setSessionAuthenticationStrategy(strategy);

        return loginFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, LoginFilter loginFilter) throws Exception {
        httpSecurity
//                .sessionManagement(session -> session.maximumSessions(1))
//                .addFilterBefore(verificationCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(new ConcurrentSessionFilter(sessionRegistry(), event -> {
                    HttpServletResponse resp = event.getResponse();
                    resp.setContentType("application/json;charset=utf-8");
                    resp.setStatus(401);
                    PrintWriter out = resp.getWriter();
                    out.write("已在其他裝置登入, 此裝置已下線");
                    out.flush();
                    out.close();
                }), ConcurrentSessionFilter.class)
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(
                        requests -> requests
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .requestMatchers("/user/**").hasRole("USER")
                                .requestMatchers("/css/**", "/js/**", "/images/**", "/getVerifyCode").permitAll()
                                .requestMatchers("/error").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(
                        form -> form
//                                .loginPage("/login.html")
                                .loginProcessingUrl("/doLogin")  // 登入接口路徑改為 "/doLogin"
                                .successHandler((request, response, authentication) -> {
                                    Object principal = authentication.getPrincipal();
                                    response.setContentType("application/json; charset=utf-8");
                                    PrintWriter printWriter = response.getWriter();
                                    Map<String, Object> responseMap = Map.of("principal", principal, "details", authentication.getDetails());
                                    printWriter.write(new ObjectMapper().writeValueAsString(responseMap));
                                    printWriter.flush();
                                    printWriter.close();
                                })
                                .failureHandler((request, response, exception) -> {
                                    response.setContentType("application/json; charset=utf-8");
                                    PrintWriter printWriter = response.getWriter();
                                    printWriter.write("登入失敗: " + exception.getMessage());
                                    printWriter.flush();
                                    printWriter.close();
                                })
                                .loginProcessingUrl("/doLogin")
                                .permitAll()
                )
                .logout(logout -> logout.logoutUrl("/doLogout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setContentType("application/json; charset=utf-8");
                            PrintWriter printWriter = response.getWriter();
                            printWriter.write("登出成功");
                            printWriter.flush();
                            printWriter.close();
                        })
                )
                .csrf(csrfConfigurer -> csrfConfigurer.disable())
                .exceptionHandling(exceptionHandler -> exceptionHandler.authenticationEntryPoint((request, response, authException) -> {
                    log.error(authException);
                    response.setContentType("application/json; charset=utf-8");
                    PrintWriter printWriter = response.getWriter();
                    printWriter.write("請先登入 " + authException.getMessage());
                    printWriter.flush();
                    printWriter.close();
                }))
                .sessionManagement(sessionManager -> sessionManager.sessionFixation().newSession())
        ;


        return httpSecurity.build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
}

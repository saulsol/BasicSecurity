package com.example.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{

         httpSecurity
                .authorizeRequests()
                .anyRequest().authenticated()
        ;

         httpSecurity
                 .formLogin();

         httpSecurity
                 .logout()
                 .logoutUrl("/logout")
                 .logoutSuccessUrl("/login")
                 .addLogoutHandler((request, response, authentication) -> {

                     HttpSession session = request.getSession();
                     session.invalidate(); // 세션 무효화

                 });
//                 .logoutSuccessHandler(  )



        return httpSecurity.build();
    }

}

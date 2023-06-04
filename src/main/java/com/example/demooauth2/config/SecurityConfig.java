package com.example.demooauth2.config;

import com.example.demooauth2.security.filter.RestAuthenticationEntryPoint;
import com.example.demooauth2.security.filter.TokenAuthenticationFilter;
import com.example.demooauth2.security.oauth2.CustomOAuth2UserService;
import com.example.demooauth2.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example.demooauth2.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.demooauth2.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.demooauth2.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository oAuth2AuthorizationRequestRepository;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

//    @Bean
//    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
//        return new HttpCookieOAuth2AuthorizationRequestRepository();
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
            throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorize")
                .authorizationRequestRepository(oAuth2AuthorizationRequestRepository)
                .and()
                .redirectionEndpoint()
                .baseUri("/oauth2/callback")
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);

        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> {
//                    auth.requestMatchers("/").permitAll();
//                    auth.requestMatchers("/favicon.ico").permitAll();
//                    auth.anyRequest().authenticated();
//                })
//                .oauth2Login(withDefaults())
//                .formLogin(withDefaults())
//                .exceptionHandling((exceptionHandling) ->
//                        exceptionHandling
//                                .accessDeniedPage("/errors/access-denied")
//                )
//                .csrf((csrf) -> csrf.disable())
//                .authorizeRequests((authorizeRequests) ->
//                        authorizeRequests
//                                .anyRequest().hasRole("USER")
//                )
//                .formLogin((formLogin) ->
//                        formLogin
//                                .permitAll()
//                )
//                .sessionManagement((sessionManagement) ->
//                        sessionManagement
//                                .sessionConcurrency((sessionConcurrency) ->
//                                        sessionConcurrency
//                                                .maximumSessions(1)
//                                                .expiredUrl("/login?expired")
//                                )
//                );
//        return http.build();
//    }

//    @Configuration
//    @EnableWebSecurity
//    public class AuthorizeUrlsSecurityConfig {
//
//
//
//        @Bean
//        public UserDetailsService userDetailsService() {
//            UserDetails user = User.withDefaultPasswordEncoder()
//                    .username("user")
//                    .password("password")
//                    .roles("USER")
//                    .build();
//            UserDetails admin = User.withDefaultPasswordEncoder()
//                    .username("admin")
//                    .password("password")
//                    .roles("ADMIN", "USER")
//                    .build();
//            return new InMemoryUserDetailsManager(user, admin);
//        }
//    }

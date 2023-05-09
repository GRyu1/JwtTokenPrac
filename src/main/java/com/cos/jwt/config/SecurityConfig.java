package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Autowired
    private final UserRepository userRepository;
    @Autowired
    private final CorsFilter corsFilter;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()// @CrossOrigin 인증되면 x , 아니면 시큐리티필터에 등록 인증 o
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new MyCustomDsl())
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/user/**").hasAnyRole("MANAGER" , "ADMIN" , "USER")
                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER" , "ADMIN" )
                .requestMatchers("/api/v1/admin/**").hasAnyRole( "ADMIN" )
                .anyRequest().permitAll()
                ;

        return http.build();
    }
    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl , HttpSecurity>{
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager =
                    builder.getSharedObject(AuthenticationManager.class);
            builder.addFilter(corsFilter)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                            .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
            super.configure(builder);
        }
    }



}
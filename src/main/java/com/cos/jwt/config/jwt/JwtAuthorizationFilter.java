package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는것이
// 권한이나 인증이 필요한 특정 주소를 요청했을때 저 필터를 거치게 되어있음
// 권한이나 인증이 필요한 주소가 아니라면 필터를 작동시키지 않음

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("jwt authorization filter");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);
        //토큰 검증 작업 시작
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer ")){
            System.out.println("토큰 유효성 검증 실패.");
            chain.doFilter(request,response);
            return;
        }
        //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
        System.out.println("debug username : "+username);
        //서명이 정상적으로 됨
        if(username != null){ // 사용자가 줌 > 이름만 받아서 써도됨 비번 확인 필요 없음 (대과거에 이미 서버측에서 준게 확인되었기 때문)
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null , principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication); //시큐리티 세션에 만들어놓은 authentication 입력해줌.

        }
        chain.doFilter(request,response);
    }
}

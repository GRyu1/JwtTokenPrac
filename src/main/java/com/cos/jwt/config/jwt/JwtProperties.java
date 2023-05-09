package com.cos.jwt.config.jwt;

public class JwtProperties {
    static String SECRET = "cos";
    static int EXPIRATION_TIME = 1000*60*10;
    static String TOKEN_PREFIX = "Bearer ";
    static String HEADER_STRING = "Authorization";

}

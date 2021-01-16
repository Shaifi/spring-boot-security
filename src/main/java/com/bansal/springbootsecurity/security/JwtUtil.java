package com.bansal.springbootsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author shaifibansal
 */
@Service
public class JwtUtil {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.expirationInMs}")
    private int expirationTimeInMs;

    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
        if(roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))){
            claims.put("isAdmin",true);
        }
        if(roles.contains(new SimpleGrantedAuthority("ROLE_USER"))){
            claims.put("isUser",true);
        }
        return doGenerateToken(claims,userDetails.getUsername());
    }

    private String doGenerateToken(Map<String,Object> claims, String subject){
        return Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTimeInMs))
                .signWith(SignatureAlgorithm.HS512,secretKey).compact();
    }
}

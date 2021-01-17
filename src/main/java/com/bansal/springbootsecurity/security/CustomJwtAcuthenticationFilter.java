package com.bansal.springbootsecurity.security;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * @author shaifibansal
 */

/**
 *
 * This class is the interceptor class and is the entry point for every request
 *
 */
@Component
public class CustomJwtAcuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        try{
            String jwtToken = extractJwtFromRequest(httpServletRequest);
            if(StringUtils.hasText(jwtToken) && jwtUtil.validateToken(jwtToken)){
                List<SimpleGrantedAuthority> roles = jwtUtil.getRolesFromToken(jwtToken);
                UserDetails userDetails = new User(jwtUtil.getUsernameFromToken(jwtToken),"",
                        roles);
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,"",roles);
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
            filterChain.doFilter(httpServletRequest,httpServletResponse);
        }catch (ExpiredJwtException e){
            httpServletRequest.setAttribute("exception",e);
        }catch (BadCredentialsException e){
            httpServletRequest.setAttribute("exception",e);
        }

    }

    private String extractJwtFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7,bearerToken.length());
        }
        return null;
    }
}

package com.bansal.springbootsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * @author shaifibansal
 */

/**
 *
 * This class is used for exception handling response and is the last point in sending response
 *
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                         AuthenticationException authenticationException) throws IOException, ServletException {

        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);

        String message;
        final Exception exception = (Exception)httpServletRequest.getAttribute("exception");

        if(exception!= null){
            if(exception.getCause() != null){
                message = exception.getCause().toString() + " " + exception.getMessage();
            }else {
                message = exception.getMessage();
            }
        }else {
            if(authenticationException.getCause() != null){
                message = authenticationException.getCause().toString() + " " + authenticationException.getMessage();
            }else {
                message = authenticationException.getMessage();
            }
        }

        byte[] body = new ObjectMapper().writeValueAsBytes(Collections.singletonMap("error",message));
        httpServletResponse.getOutputStream().write(body);
    }
}

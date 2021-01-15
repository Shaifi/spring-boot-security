package com.bansal.springbootsecurity.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * @author shaifibansal
 */

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        List<SimpleGrantedAuthority> roles = null;
        if(username.equals("admin")){
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new User(username,"$2a$10$sSiCw2.fiplrnsI9M0wzzuCwsYkHlO4q.73cFyKWlMxET7GeeiFM2",roles);
        }
        if(username.equals("user")){
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
            return new User(username,"$2a$10$v8xQtKFmcTuCHk3rbMsyZOOdVYB0beqxpQ4f/WmWEPcj2q00vH.qG",roles);
        }
        throw new UsernameNotFoundException("User not found with username " + username);
    }
}

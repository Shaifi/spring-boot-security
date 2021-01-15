package com.bansal.springbootsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author shaifibansal
 */

@RestController
public class LoginController {

    @GetMapping("/hellouser")
    public ResponseEntity<?> helloUser(){
        return new ResponseEntity<>("Hello User",HttpStatus.OK);
    }

    @GetMapping("/helloadmin")
    public ResponseEntity<?> helloAdmin(){
        return new ResponseEntity<>("Hello Admin", HttpStatus.OK);
    }
}

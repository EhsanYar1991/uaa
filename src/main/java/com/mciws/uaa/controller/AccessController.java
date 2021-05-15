package com.mciws.uaa.controller;

import com.mciws.uaa.common.GeneralResponse;
import com.mciws.uaa.common.model.AuthenticationRequest;
import com.mciws.uaa.common.model.AuthenticationResponse;
import com.mciws.uaa.util.JwtUtil;
import io.jsonwebtoken.lang.Assert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AccessController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping(value = {"/hello"}, method = RequestMethod.GET)
    public String hello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "Hello " + authentication.getName();
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestParam("username") String username, @RequestParam("password") String password) throws Exception {
        return authenticate(new AuthenticationRequest(username, password));
    }


    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(
                new GeneralResponse<>(HttpStatus.OK,
                        new AuthenticationResponse(jwt)
                )
        );
    }

    @RequestMapping(value = "/check_token", method = RequestMethod.GET)
    public ResponseEntity<?> checkToken(HttpRequest request) {
        List<String> authorizationList = request.getHeaders().get("Authorization");
        Assert.notNull(authorizationList, "Authorization must be determined");
        Assert.notEmpty(authorizationList, "Authorization must be determined");
        String authorization = authorizationList.get(0);
        final String username = jwtTokenUtil.extractUsername(authorization);
        Assert.notNull(username, "access_token is not valid.");
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(username);
        return jwtTokenUtil.validateToken(authorization, userDetails)
                ?
                ResponseEntity.ok(new GeneralResponse<>(HttpStatus.OK))
                :
                ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    @RequestMapping(value = "/user_info", method = RequestMethod.GET)
    public ResponseEntity<?> userInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.status(HttpStatus.OK).body(new GeneralResponse(HttpStatus.OK, authentication));
    }

}

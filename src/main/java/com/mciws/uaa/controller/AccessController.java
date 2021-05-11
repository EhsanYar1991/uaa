package com.mciws.uaa.controller;

import com.mciws.uaa.common.GeneralResponse;
import com.mciws.uaa.common.model.AuthenticationRequest;
import com.mciws.uaa.common.model.AuthenticationResponse;
import com.mciws.uaa.domain.redis.OnlineUser;
import com.mciws.uaa.repository.redis.OnlineUserRepository;
import com.mciws.uaa.util.JwtUtil;

import io.jsonwebtoken.lang.Assert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotBlank;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@RestController
public class AccessController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping({"/hello"})
    public String firstPage(Authentication authentication) {
        return "Hello " + authentication.getName();
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
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
    public ResponseEntity<?> checkToken(@NotBlank(message = "Authorization must be determined.") @RequestHeader("Authorization") String token) throws Exception {
        final String username = jwtTokenUtil.extractUsername(token);
        Assert.notNull(username, "access_token is not valid.");
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(username);
        return jwtTokenUtil.validateToken(token,userDetails)
                ?
                ResponseEntity.ok(new GeneralResponse<>(HttpStatus.OK))
                :
                ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    @RequestMapping(value = "/user_info", method = RequestMethod.GET)
    public ResponseEntity<?> userInfo(@NotBlank(message = "access_token must be determined.") @RequestParam("access_token") String token) throws Exception {
        final String username = jwtTokenUtil.extractUsername(token);
        Assert.notNull(username, "access_token is not valid.");
        Date expirationDate = jwtTokenUtil.extractExpiration(token);
        long diffInMillies = expirationDate.getTime() - Calendar.getInstance().getTimeInMillis();
        long diff = TimeUnit.MILLISECONDS.convert(diffInMillies, TimeUnit.MILLISECONDS);
        if (diff <= 0) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(HttpStatus.UNAUTHORIZED.getReasonPhrase());
        }
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(username);

        return ResponseEntity.ok(
                new GeneralResponse<>(HttpStatus.OK,
                        userDetails
                )
        );
    }

}

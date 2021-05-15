package com.mciws.uaa.util;

import com.mciws.uaa.domain.redis.OnlineUser;
import com.mciws.uaa.repository.redis.OnlineUserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Service
public class JwtUtil {

    @Value("${jwt.secret-key:secret}")
    private String secretKey;

    @Autowired
    private OnlineUserRepository onlineUserRepository;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(Calendar.getInstance().getTime());
        return onlineUserRepository.findById(token) == null;
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("user", userDetails);
        String token = createToken(claims, userDetails.getUsername());
        onlineUserRepository.save(new OnlineUser(token, userDetails));
        return token;
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, secretKey).compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        boolean isValidate = false;
        final String username = extractUsername(token);
        if (username.equals(userDetails.getUsername()) && !isTokenExpired(token)) {
            isValidate = true;
            onlineUserRepository.findById(token).ifPresent(onlineUser -> onlineUserRepository.save(onlineUser));
        }
        return isValidate;
    }
}
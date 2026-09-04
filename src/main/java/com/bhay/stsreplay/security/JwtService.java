package com.bhay.stsreplay.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;


@Service
public class JwtService {
    @Value("{$jwt.secret}")
    private String secret;
    @Value("${jwt.expiration-ms}")
    private long expirationMs;

    private SecretKey key(){
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(String username, String role){
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() +  expirationMs))
                .signWith(key())
                .compact();
    }

    private <T>  T extractClaims(String token, Function<Claims, T> resolver){
        Claims claims = Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload();
        return resolver.apply(claims);
    }

    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public String extractRole(String token){
        return extractClaims(token, claims -> claims.get("role", String.class));
    }

    public boolean isTokenValid(String username, String token){
        try {
            return username.equals(extractUsername(token));
        } catch (Exception e){
            return false;
        }
    }

    public boolean isExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }
}

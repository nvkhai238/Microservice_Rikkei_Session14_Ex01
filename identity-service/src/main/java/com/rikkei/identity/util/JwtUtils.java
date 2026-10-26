package com.rikkei.identity.util;

import com.rikkei.identity.config.AppProperties;
import com.rikkei.identity.entity.User;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private final Key signingKey;
    private final long accessTokenExpiration;

    public JwtUtils(AppProperties appProperties) {
        this.signingKey = Keys.hmacShaKeyFor(
            appProperties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
        this.accessTokenExpiration = appProperties.getAccessTokenExpiration();
    }

    /**
     * Generates a signed JWT access token for the given user.
     *
     * @param user the authenticated user
     * @return compact JWT string
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
            .setSubject(user.getUsername())
            .claim("role", user.getRole())
            .setIssuedAt(now)
            .setExpiration(expiry)
            .signWith(signingKey, SignatureAlgorithm.HS256)
            .compact();
    }

    /**
     * Validates the given JWT token by verifying its signature and parsing it.
     *
     * @param token the JWT string
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Extracts the username (subject) from the given JWT token.
     *
     * @param token the JWT string
     * @return the username
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(signingKey)
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }
}

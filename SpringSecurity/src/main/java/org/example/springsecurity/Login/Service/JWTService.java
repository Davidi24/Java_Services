package org.example.springsecurity.Login.Service;

import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.example.springsecurity.Login.Exeptions.UnauthorizedException;
import org.example.springsecurity.Login.model.Users;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.util.*;




@Getter
@Service
public class JWTService {

    private static final Dotenv dotenv = Dotenv.load();

    // Getter for accessKey
    private final SecretKey accessKey; // Cached access key
    // Getter for refreshKey
    private final SecretKey refreshKey; // Cached refresh key

    public JWTService() {
        String secretKey = dotenv.get("JWT_SECRET_KEY");
        String refreshSecretKey = dotenv.get("JWT_REFRESH_SECRET_KEY");

        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("JWT_SECRET_KEY is missing in .env file");
        }
        if (refreshSecretKey == null || refreshSecretKey.isEmpty()) {
            throw new IllegalStateException("JWT_REFRESH_SECRET_KEY is missing in .env file");
        }

        // Decode and cache keys
        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecretKey));
    }

    public String generateAccessToken(Users user) {
        return generateToken(user, accessKey, "access", 15 * 60 * 1000); // 15 minutes
    }

    public String generateRefreshToken(Users user) {
        return generateToken(user, refreshKey, "refresh", 30L * 24 * 60 * 60 * 1000); // 30 days
    }

    private String generateToken(Users user, SecretKey key, String tokenType, long expiration) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", tokenType);
        claims.put("unique_id", UUID.randomUUID().toString());

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails, SecretKey key) throws UnauthorizedException {
        Claims claims = getClaimsFromToken(token, key);
        final String userName = claims.getSubject();
        return (userName.equals(userDetails.getUsername()) && !claims.getExpiration().before(new Date()));
    }

    public String extractUserEmail(String token, SecretKey key) throws UnauthorizedException {
        try {
            return getClaimsFromToken(token, key).getSubject();
        } catch (Exception e) {
            throw new UnauthorizedException("Token unidentifiable");
        }
    }

    private Claims getClaimsFromToken(String token, SecretKey key) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenExpired(String token, SecretKey key) {
        Date expirationDate = getClaimsFromToken(token, key).getExpiration();
        return expirationDate.before(new Date());
    }
}

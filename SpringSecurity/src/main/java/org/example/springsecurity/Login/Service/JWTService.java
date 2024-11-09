package org.example.springsecurity.Login.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.example.springsecurity.Login.model.Users;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

@Service
public class JWTService {

    private String secretKey = "";
    @Getter
    private String refreshSecretKey = "";

    public JWTService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = keyGen.generateKey();
            secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());
            refreshSecretKey = Base64.getEncoder().encodeToString(keyGen.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Accessor methods for secret keys
    public String getAccessSecretKey() {
        return secretKey;
    }

    public String generateAccessToken(Users user) {
        return generateToken(user, secretKey, "access", 60 * 60 * 1000); // 1-hour expiration
    }

    public String generateRefreshToken(Users user) {
        return generateToken(user, refreshSecretKey, "refresh", 7 * 24 * 60 * 60 * 1000); // 7-day expiration
    }

    private String generateToken(Users user, String key, String tokenType, long expiration) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("token_type", tokenType);
        claims.put("unique_id", UUID.randomUUID().toString());

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getKey(key))
                .compact();
    }

    private SecretKey getKey(String key) {
        byte[] keyBytes = Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateToken(String token, UserDetails userDetails, String key) {
        final String userName = extractUserEmail(token, key);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token, key));
    }

    public String extractUserEmail(String token, String key) {
        return extractClaim(token, Claims::getSubject, key);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver, String key) {
        final Claims claims = extractAllClaims(token, key);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, String key) {
        return Jwts.parser()
                .verifyWith(getKey(key))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenExpired(String token, String key) {
        return extractExpiration(token, key).before(new Date());
    }

    private Date extractExpiration(String token, String key) {
        return extractClaim(token, Claims::getExpiration, key);
    }
}

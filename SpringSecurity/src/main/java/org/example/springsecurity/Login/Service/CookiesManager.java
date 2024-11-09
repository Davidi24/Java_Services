package org.example.springsecurity.Login.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CookiesManager {

    private final JWTService jwtService;

    @Autowired
    public CookiesManager(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    public void setCookies(Users user, HttpServletResponse response) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production
        accessTokenCookie.setMaxAge(60 * 60); // 1 hour
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // Set to true in production
        refreshTokenCookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
        refreshTokenCookie.setPath("/");

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    public Optional<String> getAccessTokenFromCookies(Cookie[] cookies) {
        return getTokenFromCookies(cookies, "accessToken");
    }

    public Optional<String> getRefreshTokenFromCookies(Cookie[] cookies) {
        return getTokenFromCookies(cookies, "refreshToken");
    }

    private Optional<String> getTokenFromCookies(Cookie[] cookies, String tokenName) {
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> tokenName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    public void removeCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    public void updateAccessTokenCookie(String newAccessToken, HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", newAccessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production
        accessTokenCookie.setMaxAge(60 * 60); // 1 hour
        accessTokenCookie.setPath("/");
        response.addCookie(accessTokenCookie);
    }
}
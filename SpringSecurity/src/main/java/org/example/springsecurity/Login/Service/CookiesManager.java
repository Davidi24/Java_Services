package org.example.springsecurity.Login.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CookiesManager {

    @Autowired
    private JWTService jwtService;

    public void setCookies(Users user, HttpServletResponse response) {
        String accessToken = jwtService.generateToken(user);  // Short-lived token
        System.out.println("Access token created: " + accessToken);
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production
        accessTokenCookie.setMaxAge(300); // Adjust as necessary
        accessTokenCookie.setPath("/");
        response.addCookie(accessTokenCookie);
    }

    public String getTokenFromCookies(Cookie[] cookies) {
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken")) {
                    return cookie.getValue();
                }
            }
        } else {
            System.out.println("No cookies found in the request.");
        }
        System.out.println("Token not found");
        return null;
    }

    public void removeCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");
        response.addCookie(accessTokenCookie);

        System.out.println("Access token cookie removed.");
    }
}

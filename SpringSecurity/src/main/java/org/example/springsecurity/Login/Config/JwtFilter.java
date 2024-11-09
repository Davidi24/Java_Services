package org.example.springsecurity.Login.Config;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.Service.CookiesManager;
import org.example.springsecurity.Login.Service.JWTService;
import org.example.springsecurity.Login.Service.MyUserDetailsService;
import org.example.springsecurity.Login.model.Users;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import java.util.Objects;


public class JwtFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final CookiesManager cookiesManager;
    private final ApplicationContext context;

    private final List<String> unprotectedEndpoints = List.of(
            "/authorization/login",
            "/authorization/register",
            "/notProtected"
    );

    // Constructor-based injection
    public JwtFilter(JWTService jwtService, CookiesManager cookiesManager, ApplicationContext context) {
        this.jwtService = jwtService;
        this.cookiesManager = cookiesManager;
        this.context = context;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        System.out.println("JwtFilter: Request URI = " + requestUri);  // Log request URI

        if (isUnprotectedEndpoint(requestUri)) {
            filterChain.doFilter(request, response);
            return;
        }


        String accessToken = cookiesManager.getAccessTokenFromCookies(request.getCookies());
        String refreshToken = cookiesManager.getRefreshTokenFromCookies(request.getCookies());

        System.out.println("accessToken = " + accessToken + ", refreshToken = " + refreshToken);
        if (accessToken != null) {
            String email = jwtService.extractUserEmail(accessToken, jwtService.getAccessSecretKey());
            System.out.println("email = " + email +" " + SecurityContextHolder.getContext().getAuthentication());
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(email);
                System.out.println("UserDetails = " + userDetails);
                System.out.println(jwtService.validateToken(accessToken, userDetails, jwtService.getAccessSecretKey()));
                if (jwtService.validateToken(accessToken, userDetails, jwtService.getAccessSecretKey())) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    System.out.println("here");
                    System.out.println("Authentication: " + SecurityContextHolder.getContext().getAuthentication());
                } else if (refreshToken != null && jwtService.validateToken(refreshToken, userDetails, jwtService.getRefreshSecretKey())) {
                    String newAccessToken = jwtService.generateAccessToken((Users) userDetails);
                    cookiesManager.updateAccessTokenCookie(newAccessToken, response);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    System.out.println("Access and refresh tokens are invalid.");
                }
            }
        } else {
            System.out.println("Access token not found in cookies.");
        }

        filterChain.doFilter(request, response);
    }


    private boolean isUnprotectedEndpoint(String requestUri) {
        return unprotectedEndpoints.stream().anyMatch(endpoint -> endpoint.equals(requestUri));
    }
}

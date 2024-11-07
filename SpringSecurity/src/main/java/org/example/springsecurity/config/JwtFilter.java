package org.example.springsecurity.config;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Repository.UserRepository;
import org.example.springsecurity.service.JWTService;
import org.example.springsecurity.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Objects;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        System.out.println("JwtFilter: Request URI = " + requestUri);  // Log request URI

        if (Objects.equals(request.getRequestURI(), "/authorization/login")) {
            System.out.println("Login process started...");
            filterChain.doFilter(request, response);
            System.out.println("Login process finished.");
            return;
        }

        if (Objects.equals(request.getRequestURI(), "/authorization/register")) {
            System.out.println("Register process started...");
            filterChain.doFilter(request, response);
            return;
        }

        if (request.getCookies() != null) {
            Cookie[] cookies = request.getCookies();
            String token = getTokenFromCookies(cookies);
            if (token != null) {
                String email = jwtService.extractUserEmail(token);
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(email);
                    if (jwtService.validateToken(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource()
                                .buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            } else {
                System.out.println("Token not found");
                filterChain.doFilter(request, response);
                return;
            }
        }
        filterChain.doFilter(request, response); // Ensure the filter chain continues
    }

    private String getTokenFromCookies(Cookie[] cookies) {
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

}

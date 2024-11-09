package org.example.springsecurity.Login.Config;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.Exeptions.UnauthorizedException;
import org.example.springsecurity.Login.Service.CookiesManager;
import org.example.springsecurity.Login.Service.JWTService;
import org.example.springsecurity.Login.Service.MyUserDetailsService;
import org.example.springsecurity.Login.model.UserPrincipal;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Set;

public class JwtFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final CookiesManager cookiesManager;
    private final MyUserDetailsService userDetailsService;
    private UserDetails userDetails;

    private final Set<String> unprotectedEndpoints = Set.of(
            "/authorization/login",
            "/authorization/register",
            "/notProtected"
    );

    public JwtFilter(JWTService jwtService, CookiesManager cookiesManager, MyUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.cookiesManager = cookiesManager;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();

        if (isUnprotectedEndpoint(requestUri)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            handleAccessToken(request, response);
        } catch (UnauthorizedException e) {
            setUnauthorizedResponse(response);
            return;
        } catch (JwtException e) {
            handleRefreshToken(request, response);
        } catch (Exception e) {
            setInternalServerErrorResponse(response);
        }

        filterChain.doFilter(request, response);
    }

    private void handleAccessToken(HttpServletRequest request, HttpServletResponse response) throws UnauthorizedException {
        cookiesManager.getAccessTokenFromCookies(request.getCookies()).ifPresentOrElse(accessToken -> {
            try {
                String email = jwtService.extractUserEmail(accessToken, jwtService.getAccessKey());
                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    userDetails = userDetailsService.loadUserByUsername(email);
                    if (jwtService.validateToken(accessToken, userDetails, jwtService.getAccessKey())) {
                        setAuthentication(request, userDetails);
                    }
                }
            } catch (Exception e) {
                throw new JwtException("Invalid access token", e);
            }
        }, () -> {
            setUnauthorizedResponse(response);
            throw new UnauthorizedException("Unauthorized");

        });
    }

    private void handleRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        cookiesManager.getRefreshTokenFromCookies(request.getCookies()).ifPresentOrElse(refreshToken -> {
            if (jwtService.validateToken(refreshToken, userDetails, jwtService.getRefreshKey())) {
                String email = jwtService.extractUserEmail(refreshToken, jwtService.getRefreshKey());
                userDetails = userDetailsService.loadUserByUsername(email);
                String newAccessToken = jwtService.generateAccessToken(((UserPrincipal) userDetails).getUser());
                cookiesManager.updateAccessTokenCookie(newAccessToken, response);
                setAuthentication(request, userDetails);
            } else {
                throw new UnauthorizedException("Invalid or expired refresh token");
            }
        }, () -> {
            setUnauthorizedResponse(response);
            throw new UnauthorizedException("No refresh token found");
        });
    }

    private void setAuthentication(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private boolean isUnprotectedEndpoint(String requestUri) {
        return unprotectedEndpoints.contains(requestUri);
    }

    private void setUnauthorizedResponse(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void setInternalServerErrorResponse(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
}

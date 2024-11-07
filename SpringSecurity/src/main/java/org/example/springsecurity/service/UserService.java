package org.example.springsecurity.service;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Repository.UserRepository;
import org.example.springsecurity.Validation.Validation;
import org.example.springsecurity.model.UserPrincipal;
import org.example.springsecurity.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private JWTService jwtService;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    //neds checks on the return
    public int register(Users user) {
        String isValid = Validation.validateUser(user);
        if (!isValid.isEmpty()) {
            return -2;
        }
        Users existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser != null) {
            return 0;
        }

        try {
            String hashedPassword = encoder.encode(user.getPassword());
            user.setPassword(hashedPassword);
            userRepository.save(user);
            return 1;
        } catch (Exception e) {
            System.out.println("Exeption in login: " + e.getMessage());
            return -1;
        }
    }

    public Users login(Users user, HttpServletResponse response) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserPrincipal) {
                Users authenticatedUser = ((UserPrincipal) principal).user();
                setCookies(authenticatedUser, response);
                return authenticatedUser;
            }
        }
        return null;
    }

    //verification in the production
    private void setCookies(Users user, HttpServletResponse response) {
        String accessToken = jwtService.generateToken(user);  // Short-lived token
        System.out.println("Access token created: " + accessToken);
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production
        accessTokenCookie.setMaxAge(300); // Adjust as necessary
        accessTokenCookie.setPath("/");
        response.addCookie(accessTokenCookie);
    }

}

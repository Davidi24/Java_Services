package org.example.springsecurity.Login.Service;

import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.DTO.DTOMaper.UserMapper;
import org.example.springsecurity.Login.DTO.DTOModel.UserDTO;
import org.example.springsecurity.Login.Repository.UserRepository;
import org.example.springsecurity.Login.Validation.Validation;
import org.example.springsecurity.Login.model.UserPrincipal;
import org.example.springsecurity.Login.model.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {


    private final CookiesManager  cookiesManager;
    private final AuthenticationManager authManager;
    private final  UserRepository userRepository;
    private final  UserMapper userMapper;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    @Autowired
    public UserService(CookiesManager cookiesManager, AuthenticationManager authManager, UserRepository userRepository, UserMapper userMapper) {
        this.cookiesManager = cookiesManager;
        this.authManager = authManager;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }

    public String register(Users user) {
        String isValid = Validation.validateUser(user);
        if (!isValid.isEmpty()) {
            return "User is not valid";
        }
        Users existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser != null) {
            return "User is already registered";
        }

        try {
            String hashedPassword = encoder.encode(user.getPassword());
            user.setPassword(hashedPassword);
            userRepository.save(user);
            return "User registered successfully";
        } catch (Exception e) {
            System.out.println("Exeption in login: " + e.getMessage());
            return "Something went wrong";
        }
    }

    public UserDTO login(Users user, HttpServletResponse response) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserPrincipal) {
                Users authenticatedUser = ((UserPrincipal) principal).user();
                cookiesManager.setCookies(authenticatedUser, response);
                return userMapper.usersToUserDTO(authenticatedUser);
            }
        }
        return null;
    }

    public void logout(HttpServletResponse response) {
        cookiesManager.removeCookies(response);
    }

}

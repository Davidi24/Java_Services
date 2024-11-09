package org.example.springsecurity.Login.Controller;

import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.DTO.DTOModel.UserDTO;
import org.example.springsecurity.Login.model.Users;
import org.example.springsecurity.Login.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
@RequestMapping("/authorization")
public class UserController {

    @Autowired
    private UserService service;


    @PostMapping("/register")
    public int register(@RequestBody Users user) {
        return service.register(user);

    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Users user, HttpServletResponse response) {
        try {
            UserDTO userDto = service.login(user, response);
            return ResponseEntity.ok(userDto);
        } catch (Exception e) {
            if(Objects.equals(e.getMessage(), "Bad credentials")){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            System.out.println("Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Server error");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        try {
            service.logout(response);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while logging out");
        }
    }







}

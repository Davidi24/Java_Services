package org.example.springsecurity.Login.Controller;

import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.Login.DTO.DTOModel.UserDTO;
import org.example.springsecurity.Login.model.Users;
import org.example.springsecurity.Login.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public UserDTO login(@RequestBody Users user, HttpServletResponse response) {
        return service.login(user, response);
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
         service.logout(response);
    }
}
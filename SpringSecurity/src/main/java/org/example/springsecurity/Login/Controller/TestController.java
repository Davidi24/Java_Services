package org.example.springsecurity.Login.Controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/protected")
    public ResponseEntity<?> protectedMethod() {
        return ResponseEntity.status(HttpStatus.OK).body("oki Doki");
    }

    @GetMapping("/notProtected")
    public String notProtectedMethod() {
        return "Hello";
    }
}

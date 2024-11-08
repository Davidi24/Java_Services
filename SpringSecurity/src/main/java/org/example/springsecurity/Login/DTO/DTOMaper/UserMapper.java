package org.example.springsecurity.Login.DTO.DTOMaper;

import org.example.springsecurity.Login.DTO.DTOModel.UserDTO;
import org.example.springsecurity.Login.model.Users;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public  UserDTO usersToUserDTO(Users users) {
        if (users == null) {
            return null;
        }
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(users.getUsername());
        userDTO.setEmail(users.getEmail());
        userDTO.setPhoneNumer(users.getPhoneNumer());
        userDTO.setAddress(users.getAddress());
        return userDTO;
    }
}

package org.example.springsecurity.Login.model;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "userss")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Users {
    @Id
    private ObjectId id;
    private String username;
    private String password;
    private String email;
    private String phoneNumer;
    private String address;
}

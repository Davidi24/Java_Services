package org.example.springsecurity.Login.Repository;
import org.example.springsecurity.Login.model.Users;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends MongoRepository<Users, Integer> {
    Users findByEmail(String email);
}

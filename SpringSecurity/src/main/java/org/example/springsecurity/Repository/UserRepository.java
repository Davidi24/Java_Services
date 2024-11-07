package org.example.springsecurity.Repository;
import org.example.springsecurity.model.Users;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends MongoRepository<Users, Integer> {
    Users findByEmail(String email);
}

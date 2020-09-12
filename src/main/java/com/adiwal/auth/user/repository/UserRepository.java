package com.adiwal.auth.user.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.adiwal.auth.user.model.User;

public interface UserRepository extends MongoRepository<User, String> {

	User findByUsername(String username);

}

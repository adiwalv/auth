package com.adiwal.auth.repository

import com.adiwal.auth.entity.Users

import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.data.rest.core.annotation.RepositoryRestResource

@RepositoryRestResource(path = "users", collectionResourceRel = "users", itemResourceRel = "users")
interface UsersRepository : MongoRepository<Users, String> {
    fun findByUsername(username: String): Users
}
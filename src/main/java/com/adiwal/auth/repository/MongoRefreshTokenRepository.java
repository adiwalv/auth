package com.adiwal.auth.repository;

import com.adiwal.auth.domain.MongoAccessToken;
import com.adiwal.auth.domain.MongoRefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MongoRefreshTokenRepository extends MongoRepository<MongoRefreshToken, String> {
    Optional<MongoRefreshToken> findByTokenId(String tokenId);
}

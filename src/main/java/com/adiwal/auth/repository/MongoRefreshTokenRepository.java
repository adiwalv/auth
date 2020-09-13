package com.adiwal.auth.repository;

import com.adiwal.auth.domain.refreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MongoRefreshTokenRepository extends MongoRepository<refreshToken, String> {
    Optional<refreshToken> findByTokenId(String tokenId);
}

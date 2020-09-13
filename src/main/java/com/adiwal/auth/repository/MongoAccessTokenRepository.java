package com.adiwal.auth.repository;

import com.adiwal.auth.domain.AuthClientDetails;
import com.adiwal.auth.domain.MongoAccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MongoAccessTokenRepository extends MongoRepository<MongoAccessToken, String> {
    Optional<MongoAccessToken> findByTokenId(String tokenId);
}
